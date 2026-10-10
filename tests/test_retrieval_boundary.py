"""Integration tests for ID-only candidate selection and authorization."""

import unittest

from authorization_boundary import Outcome, VerifiedIdentity
from retrieval_boundary import InMemoryCandidateProvider, search_with_candidates


class FakeDependencies:
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
            "allowed-id": "AUTHORIZED TEXT",
            "denied-id": "SECRET PROTECTED TEXT",
        }

    def authenticate(self, credential):
        if credential != "demo-credential":
            return None
        return VerifiedIdentity("user-1", True)

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

    def search(self, query, credential, provider):
        return search_with_candidates(
            query,
            credential,
            candidate_provider=provider,
            authenticate=self.authenticate,
            load_user_metadata=self.load_user_metadata,
            load_document_metadata=self.load_document_metadata,
            load_protected_content=self.load_protected_content,
        )


class CandidateRetrievalBoundaryTests(unittest.TestCase):
    def test_provider_returns_document_ids_only(self):
        provider = InMemoryCandidateProvider(
            {"question": ("allowed-id", "denied-id")}
        )

        candidates = provider.select_candidate_ids("question")

        self.assertEqual(candidates, ("allowed-id", "denied-id"))
        self.assertTrue(all(type(item) is str for item in candidates))
        self.assertNotIn("AUTHORIZED TEXT", repr(candidates))
        self.assertNotIn("SECRET PROTECTED TEXT", repr(candidates))

    def test_search_returns_only_authorized_content_for_downstream_values(self):
        dependencies = FakeDependencies()
        provider = InMemoryCandidateProvider(
            {"question": ("allowed-id", "denied-id")}
        )

        result = dependencies.search("question", "demo-credential", provider)

        self.assertIs(result.outcome, Outcome.ALLOWED)
        self.assertEqual([item.document_id for item in result.documents], ["allowed-id"])
        self.assertEqual(dependencies.content_calls, ["allowed-id"])
        # These stand-ins model snippets, citations, and future model context.
        snippets = [item.content[:10] for item in result.documents]
        citations = [item.document_id for item in result.documents]
        model_context = " ".join(item.content for item in result.documents)
        self.assertEqual(snippets, ["AUTHORIZED"])
        self.assertEqual(citations, ["allowed-id"])
        self.assertIn("AUTHORIZED TEXT", model_context)
        self.assertNotIn("SECRET PROTECTED TEXT", repr(result))
        self.assertNotIn("SECRET PROTECTED TEXT", repr(snippets + citations + [model_context]))

    def test_unverified_identity_causes_no_metadata_or_content_lookups(self):
        dependencies = FakeDependencies()
        provider = InMemoryCandidateProvider({"question": ("allowed-id",)})

        result = dependencies.search("question", "not-a-credential", provider)

        self.assertIs(result.outcome, Outcome.DENIED)
        self.assertEqual(dependencies.user_calls, 0)
        self.assertEqual(dependencies.document_calls, [])
        self.assertEqual(dependencies.content_calls, [])

    def test_candidate_metadata_failure_fails_search_before_content_loading(self):
        dependencies = FakeDependencies()
        dependencies.document_errors["denied-id"] = TimeoutError("RAW LOOKUP SECRET")
        provider = InMemoryCandidateProvider(
            {"question": ("allowed-id", "denied-id")}
        )

        result = dependencies.search("question", "demo-credential", provider)

        self.assertIs(result.outcome, Outcome.DEPENDENCY_FAILURE)
        self.assertEqual(result.documents, ())
        self.assertEqual(dependencies.content_calls, [])
        self.assertNotIn("RAW LOOKUP SECRET", repr(result))
        self.assertNotIn("AUTHORIZED TEXT", repr(result))

    def test_content_loader_failure_withholds_partial_search_result(self):
        dependencies = FakeDependencies()
        dependencies.content_errors["denied-id"] = RuntimeError("RAW CONTENT SECRET")
        # Both documents pass policy so the second loader fails after the first.
        dependencies.document_records["denied-id"] = {
            "sensitivity": "medium",
            "access_type": "public",
        }
        provider = InMemoryCandidateProvider(
            {"question": ("allowed-id", "denied-id")}
        )

        result = dependencies.search("question", "demo-credential", provider)

        self.assertIs(result.outcome, Outcome.DEPENDENCY_FAILURE)
        self.assertEqual(result.documents, ())
        self.assertEqual(dependencies.content_calls, ["allowed-id", "denied-id"])
        self.assertNotIn("RAW CONTENT SECRET", repr(result))
        self.assertNotIn("AUTHORIZED TEXT", repr(result))

    def test_provider_failure_is_generic_and_contains_no_protected_data(self):
        class FailingProvider:
            def select_candidate_ids(self, query):
                raise RuntimeError("SECRET PROTECTED TEXT AND RAW FAILURE")

        dependencies = FakeDependencies()

        result = dependencies.search("question", "demo-credential", FailingProvider())

        self.assertIs(result.outcome, Outcome.DEPENDENCY_FAILURE)
        self.assertEqual(result.documents, ())
        self.assertEqual(dependencies.user_calls, 0)
        self.assertEqual(dependencies.document_calls, [])
        self.assertEqual(dependencies.content_calls, [])
        self.assertNotIn("RAW FAILURE", repr(result))
        self.assertNotIn("SECRET PROTECTED TEXT", repr(result))


if __name__ == "__main__":
    unittest.main()
