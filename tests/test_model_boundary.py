"""Tests for safe model-input construction using authorized search results."""

import json
import unittest
from unittest.mock import patch

from authorization_boundary import (
    AuthorizedContent,
    BoundaryResult,
    Outcome,
)
from model_boundary import RecordingModel, search_and_record
from retrieval_boundary import InMemoryCandidateProvider
from test_retrieval_boundary import FakeDependencies


class ModelBoundaryTests(unittest.TestCase):
    def run_search(self, dependencies, provider, model, credential="demo-credential"):
        return search_and_record(
            "question",
            credential,
            candidate_provider=provider,
            authenticate=dependencies.authenticate,
            load_user_metadata=dependencies.load_user_metadata,
            load_document_metadata=dependencies.load_document_metadata,
            load_protected_content=dependencies.load_protected_content,
            model=model,
        )

    def test_authorized_content_reaches_model_after_successful_authorization(self):
        dependencies = FakeDependencies()
        provider = InMemoryCandidateProvider({"question": ("allowed-id",)})
        model = RecordingModel()

        result = self.run_search(dependencies, provider, model)

        self.assertIs(result.outcome, Outcome.ALLOWED)
        self.assertEqual(result.response, "Recorded model response.")
        self.assertEqual(dependencies.content_calls, ["allowed-id"])
        self.assertEqual(len(model.inputs), 1)
        payload = json.loads(model.inputs[0])
        self.assertEqual(payload["documents"], [
            {"document_id": "allowed-id", "content": "AUTHORIZED TEXT"}
        ])

    def test_mixed_search_sends_authorized_content_only(self):
        dependencies = FakeDependencies()
        provider = InMemoryCandidateProvider(
            {"question": ("allowed-id", "denied-id")}
        )
        model = RecordingModel()

        result = self.run_search(dependencies, provider, model)

        self.assertIs(result.outcome, Outcome.ALLOWED)
        self.assertEqual(dependencies.content_calls, ["allowed-id"])
        self.assertEqual(len(model.inputs), 1)
        serialized_input = model.inputs[0]
        payload = json.loads(serialized_input)
        self.assertEqual(
            [item["document_id"] for item in payload["documents"]],
            ["allowed-id"],
        )
        self.assertIn("AUTHORIZED TEXT", serialized_input)
        self.assertNotIn("denied-id", serialized_input)
        self.assertNotIn("SECRET PROTECTED TEXT", serialized_input)

    def test_denied_and_empty_results_do_not_invoke_model(self):
        cases = (
            {"question": ("denied-id",)},
            {"other-question": ("allowed-id",)},
        )
        for candidates in cases:
            with self.subTest(candidates=candidates):
                dependencies = FakeDependencies()
                provider = InMemoryCandidateProvider(candidates)
                model = RecordingModel()

                result = self.run_search(dependencies, provider, model)

                self.assertIs(result.outcome, Outcome.DENIED)
                self.assertIsNone(result.response)
                self.assertEqual(model.inputs, [])
                self.assertEqual(dependencies.content_calls, [])

    def test_metadata_exception_or_timeout_prevents_model_and_content_disclosure(self):
        for error in (
            RuntimeError("RAW METADATA SECRET"),
            TimeoutError("RAW TIMEOUT SECRET"),
        ):
            with self.subTest(error_type=type(error).__name__):
                dependencies = FakeDependencies()
                dependencies.document_errors["denied-id"] = error
                provider = InMemoryCandidateProvider(
                    {"question": ("allowed-id", "denied-id")}
                )
                model = RecordingModel()

                result = self.run_search(dependencies, provider, model)

                self.assertIs(result.outcome, Outcome.DEPENDENCY_FAILURE)
                self.assertIsNone(result.response)
                self.assertEqual(model.inputs, [])
                self.assertEqual(dependencies.content_calls, [])
                self.assertNotIn("RAW METADATA SECRET", repr(result))
                self.assertNotIn("RAW TIMEOUT SECRET", repr(result))
                self.assertNotIn("AUTHORIZED TEXT", repr(result))

    def test_content_loader_failure_prevents_model_and_partial_disclosure(self):
        dependencies = FakeDependencies()
        dependencies.content_errors["allowed-id"] = RuntimeError("RAW CONTENT SECRET")
        provider = InMemoryCandidateProvider({"question": ("allowed-id",)})
        model = RecordingModel()

        result = self.run_search(dependencies, provider, model)

        self.assertIs(result.outcome, Outcome.DEPENDENCY_FAILURE)
        self.assertIsNone(result.response)
        self.assertEqual(dependencies.content_calls, ["allowed-id"])
        self.assertEqual(model.inputs, [])
        self.assertNotIn("RAW CONTENT SECRET", repr(result))
        self.assertNotIn("AUTHORIZED TEXT", repr(result))

    def test_missing_or_unverified_identity_stops_all_downstream_calls(self):
        for credential in (None, "not-a-credential"):
            with self.subTest(credential=credential):
                dependencies = FakeDependencies()
                provider = InMemoryCandidateProvider({"question": ("allowed-id",)})
                model = RecordingModel()

                result = self.run_search(dependencies, provider, model, credential)

                self.assertIs(result.outcome, Outcome.DENIED)
                self.assertEqual(dependencies.user_calls, 0)
                self.assertEqual(dependencies.document_calls, [])
                self.assertEqual(dependencies.content_calls, [])
                self.assertEqual(model.inputs, [])

    def test_malformed_or_unexpected_search_results_fail_closed(self):
        malformed_results = (
            None,
            BoundaryResult(outcome=Outcome.ALLOWED, documents=[]),
            BoundaryResult(
                outcome=Outcome.ALLOWED,
                documents=(AuthorizedContent("allowed-id", object()),),
            ),
            BoundaryResult(outcome="allowed", documents=()),
        )
        dependencies = FakeDependencies()
        provider = InMemoryCandidateProvider({"question": ("allowed-id",)})

        for search_result in malformed_results:
            with self.subTest(search_result=search_result):
                model = RecordingModel()
                with patch("model_boundary.search_with_candidates", return_value=search_result):
                    result = self.run_search(dependencies, provider, model)

                self.assertIs(result.outcome, Outcome.DEPENDENCY_FAILURE)
                self.assertIsNone(result.response)
                self.assertEqual(model.inputs, [])

    def test_empty_or_whitespace_content_fails_before_model_invocation(self):
        for content in ("", " \t\n "):
            with self.subTest(content=repr(content)):
                dependencies = FakeDependencies()
                provider = InMemoryCandidateProvider({"question": ("allowed-id",)})
                model = RecordingModel()
                malformed_result = BoundaryResult(
                    outcome=Outcome.ALLOWED,
                    documents=(AuthorizedContent("allowed-id", content),),
                )

                with patch(
                    "model_boundary.search_with_candidates",
                    return_value=malformed_result,
                ):
                    result = self.run_search(dependencies, provider, model)

                self.assertIs(result.outcome, Outcome.DEPENDENCY_FAILURE)
                self.assertIsNone(result.response)
                self.assertEqual(model.inputs, [])
                self.assertNotIn("AUTHORIZED TEXT", repr(result))
                if content:
                    self.assertNotIn(content, repr(result))

    def test_model_exception_returns_generic_failure_without_leaking_details(self):
        class FailingModel:
            def generate(self, model_input):
                raise RuntimeError("RAW MODEL DETAIL AUTHORIZED TEXT")

        dependencies = FakeDependencies()
        provider = InMemoryCandidateProvider({"question": ("allowed-id",)})
        model = FailingModel()

        result = self.run_search(dependencies, provider, model)

        self.assertIs(result.outcome, Outcome.DEPENDENCY_FAILURE)
        self.assertIsNone(result.response)
        self.assertNotIn("RAW MODEL DETAIL", repr(result))
        self.assertNotIn("AUTHORIZED TEXT", repr(result))

    def test_non_string_model_response_returns_generic_failure_without_leaking_data(self):
        class NonStringModel:
            def generate(self, model_input):
                return {"detail": "RAW MODEL VALUE AUTHORIZED TEXT"}

        dependencies = FakeDependencies()
        provider = InMemoryCandidateProvider({"question": ("allowed-id",)})

        result = self.run_search(dependencies, provider, NonStringModel())

        self.assertIs(result.outcome, Outcome.DEPENDENCY_FAILURE)
        self.assertIsNone(result.response)
        self.assertNotIn("RAW MODEL VALUE", repr(result))
        self.assertNotIn("AUTHORIZED TEXT", repr(result))

    def test_recording_model_stores_exact_input_and_returns_fixed_response(self):
        model = RecordingModel(response="fixed reply")
        exact_input = '{"documents":[{"content":"sample","document_id":"doc-1"}]}'

        response = model.generate(exact_input)

        self.assertEqual(model.inputs, [exact_input])
        self.assertEqual(response, "fixed reply")


if __name__ == "__main__":
    unittest.main()
