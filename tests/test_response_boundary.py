"""Tests for safe local snippets and citations from authorized search results."""

import io
import unittest
from contextlib import redirect_stdout

from authorization_boundary import Outcome, VerifiedIdentity
from retrieval_boundary import InMemoryCandidateProvider
from response_boundary import SNIPPET_LENGTH, search_and_preview


class FakeDependencies:
    """Small in-memory records and counters for response-boundary tests."""

    def __init__(self):
        self.user_calls = 0
        self.document_calls = []
        self.content_calls = []
        self.document_errors = {}
        self.content_errors = {}
        self.user_record = {
            "identity": "user-1",
            "is_active": True,
            "clearance": "medium",
            "role": "user",
            "department": "engineering",
        }
        self.document_records = {
            "allowed-id": {
                "sensitivity": "medium",
                "access_type": "public",
            },
            "denied-id": {
                "sensitivity": "medium",
                "access_type": "department_restricted",
                "department": "finance",
            },
        }
        self.contents = {
            "allowed-id": "A" * (SNIPPET_LENGTH + 10),
            "denied-id": "DENIED CONTENT MARKER",
        }

    def authenticate(self, credential):
        if credential == "demo-credential":
            return VerifiedIdentity("user-1", True)
        return None

    def load_user_metadata(self, subject):
        self.user_calls += 1
        return self.user_record

    def load_document_metadata(self, document_id):
        self.document_calls.append(document_id)
        error = self.document_errors.get(document_id)
        if error:
            raise error
        return self.document_records.get(document_id)

    def load_protected_content(self, document_id):
        self.content_calls.append(document_id)
        error = self.content_errors.get(document_id)
        if error:
            raise error
        return self.contents[document_id]

    def preview(self, query, identity, provider):
        return search_and_preview(
            query,
            identity,
            candidate_provider=provider,
            authenticate=self.authenticate,
            load_user_metadata=self.load_user_metadata,
            load_document_metadata=self.load_document_metadata,
            load_protected_content=self.load_protected_content,
        )


class ResponseBoundaryTests(unittest.TestCase):
    def provider(self, *document_ids):
        return InMemoryCandidateProvider({"question": tuple(document_ids)})

    def test_allowed_response_has_snippet_and_citation_from_authorized_result(self):
        dependencies = FakeDependencies()

        preview = dependencies.preview(
            "question", "demo-credential", self.provider("allowed-id")
        )

        self.assertIs(preview.outcome, Outcome.ALLOWED)
        self.assertEqual(len(preview.snippets), 1)
        self.assertEqual(preview.snippets[0].document_id, "allowed-id")
        self.assertEqual(preview.snippets[0].text, "A" * SNIPPET_LENGTH + "...")
        self.assertEqual(preview.citations, ("allowed-id",))
        self.assertEqual(dependencies.content_calls, ["allowed-id"])

    def test_mixed_search_outputs_only_authorized_candidate(self):
        dependencies = FakeDependencies()

        preview = dependencies.preview(
            "question", "demo-credential", self.provider("allowed-id", "denied-id")
        )

        self.assertIs(preview.outcome, Outcome.ALLOWED)
        self.assertEqual(preview.citations, ("allowed-id",))
        self.assertEqual([item.document_id for item in preview.snippets], ["allowed-id"])
        self.assertEqual(dependencies.content_calls, ["allowed-id"])
        self.assertNotIn("denied-id", repr(preview))
        self.assertNotIn("DENIED CONTENT MARKER", repr(preview))

    def test_denied_and_empty_results_have_no_protected_output(self):
        dependencies = FakeDependencies()
        denied_provider = self.provider("denied-id")
        empty_provider = self.provider()

        denied = dependencies.preview("question", "demo-credential", denied_provider)
        empty = dependencies.preview("question", "demo-credential", empty_provider)

        self.assertIs(denied.outcome, Outcome.DENIED)
        self.assertEqual(denied.snippets, ())
        self.assertEqual(denied.citations, ())
        self.assertIs(empty.outcome, Outcome.DENIED)
        self.assertEqual(empty.snippets, ())
        self.assertEqual(empty.citations, ())
        self.assertEqual(dependencies.content_calls, [])

    def test_metadata_exception_or_timeout_returns_no_output_and_loads_no_content(self):
        for error in (RuntimeError("RAW LOOKUP DETAIL"), TimeoutError("RAW TIMEOUT DETAIL")):
            with self.subTest(error=type(error).__name__):
                dependencies = FakeDependencies()
                dependencies.document_errors["denied-id"] = error
                output = io.StringIO()
                with redirect_stdout(output):
                    preview = dependencies.preview(
                        "question",
                        "demo-credential",
                        self.provider("allowed-id", "denied-id"),
                    )

                self.assertIs(preview.outcome, Outcome.DEPENDENCY_FAILURE)
                self.assertEqual(preview.snippets, ())
                self.assertEqual(preview.citations, ())
                self.assertEqual(dependencies.content_calls, [])
                self.assertNotIn("RAW", repr(preview) + output.getvalue())
                self.assertNotIn("A" * 20, repr(preview) + output.getvalue())

    def test_content_loader_failure_withholds_partial_response(self):
        dependencies = FakeDependencies()
        dependencies.document_records["denied-id"] = {
            "sensitivity": "medium",
            "access_type": "public",
        }
        dependencies.content_errors["denied-id"] = RuntimeError("RAW CONTENT ERROR")
        output = io.StringIO()
        with redirect_stdout(output):
            preview = dependencies.preview(
                "question",
                "demo-credential",
                self.provider("allowed-id", "denied-id"),
            )

        self.assertIs(preview.outcome, Outcome.DEPENDENCY_FAILURE)
        self.assertEqual(preview.snippets, ())
        self.assertEqual(preview.citations, ())
        self.assertEqual(dependencies.content_calls, ["allowed-id", "denied-id"])
        self.assertNotIn("RAW CONTENT ERROR", repr(preview) + output.getvalue())
        self.assertNotIn("A" * 20, repr(preview) + output.getvalue())

    def test_missing_or_unverified_identity_causes_no_lookups_or_output(self):
        for identity in (None, "bad-credential"):
            with self.subTest(identity=identity):
                dependencies = FakeDependencies()
                preview = dependencies.preview(
                    "question", identity, self.provider("allowed-id")
                )
                self.assertIs(preview.outcome, Outcome.DENIED)
                self.assertEqual(preview.snippets, ())
                self.assertEqual(preview.citations, ())
                self.assertEqual(dependencies.user_calls, 0)
                self.assertEqual(dependencies.document_calls, [])
                self.assertEqual(dependencies.content_calls, [])

    def test_malformed_or_unexpected_boundary_results_fail_closed(self):
        from unittest.mock import patch

        from authorization_boundary import AuthorizedContent, BoundaryResult

        malformed_results = (
            None,
            BoundaryResult(Outcome.ALLOWED, ()),
            BoundaryResult(Outcome.ALLOWED, [AuthorizedContent("id", "text")]),
            BoundaryResult(Outcome.ALLOWED, (object(),)),
            BoundaryResult(Outcome.ALLOWED, (AuthorizedContent("id", "  "),)),
            BoundaryResult("allowed", (AuthorizedContent("id", "secret"),)),
        )
        for result in malformed_results:
            with self.subTest(result_type=type(result).__name__):
                with patch("response_boundary.search_with_candidates", return_value=result):
                    preview = search_and_preview(
                        "question",
                        "demo-credential",
                        candidate_provider=self.provider("allowed-id"),
                        authenticate=lambda value: None,
                        load_user_metadata=lambda value: None,
                        load_document_metadata=lambda value: None,
                        load_protected_content=lambda value: None,
                    )
                self.assertIs(preview.outcome, Outcome.DEPENDENCY_FAILURE)
                self.assertEqual(preview.snippets, ())
                self.assertEqual(preview.citations, ())
                self.assertNotIn("secret", repr(preview))

    def test_failure_output_does_not_contain_denied_content_or_raw_error(self):
        dependencies = FakeDependencies()
        dependencies.document_errors["denied-id"] = RuntimeError(
            "RAW EXCEPTION DETAIL DENIED CONTENT MARKER"
        )
        output = io.StringIO()
        with redirect_stdout(output):
            preview = dependencies.preview(
                "question", "demo-credential", self.provider("denied-id")
            )

        self.assertIs(preview.outcome, Outcome.DEPENDENCY_FAILURE)
        self.assertNotIn("RAW EXCEPTION DETAIL", repr(preview) + output.getvalue())
        self.assertNotIn("DENIED CONTENT MARKER", repr(preview) + output.getvalue())


if __name__ == "__main__":
    unittest.main()
