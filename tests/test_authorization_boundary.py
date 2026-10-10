"""Tests for the simulated authorization boundary and failure handling."""

import unittest

from authorization_boundary import (
    Outcome,
    VerifiedIdentity,
    authorize_document,
    authorize_search,
)


class FakeDependencies:
    """Small in-memory dependencies; no real authentication or data service."""

    def __init__(self):
        self.user_record = {
            "identity": "user-1",
            "is_active": True,
            "clearance": "medium",
            "role": "user",
            "department": "engineering",
        }
        self.document_records = {
            "public-doc": {
                "sensitivity": "medium",
                "access_type": "public",
            },
            "engineering-doc": {
                "sensitivity": "medium",
                "access_type": "department_restricted",
                "department": "engineering",
            },
            "finance-doc": {
                "sensitivity": "medium",
                "access_type": "department_restricted",
                "department": "finance",
            },
        }
        self.contents = {
            "public-doc": "PROTECTED PUBLIC CONTENT",
            "engineering-doc": "PROTECTED ENGINEERING CONTENT",
            "finance-doc": "PROTECTED FINANCE CONTENT",
        }
        self.authentication_result = VerifiedIdentity("user-1", True)
        self.authentication_error = None
        self.user_error = None
        self.document_error_for = {}
        self.content_error_for = {}
        self.user_calls = 0
        self.document_calls = []
        self.content_calls = []

    def authenticate(self, supplied_identity):
        if self.authentication_error is not None:
            raise self.authentication_error
        if supplied_identity != "demo-credential":
            return None
        return self.authentication_result

    def load_user_metadata(self, subject):
        self.user_calls += 1
        if self.user_error is not None:
            raise self.user_error
        if self.user_record is None:
            return None
        return self.user_record

    def load_document_metadata(self, document_id):
        self.document_calls.append(document_id)
        error = self.document_error_for.get(document_id)
        if error is not None:
            raise error
        return self.document_records.get(document_id)

    def load_protected_content(self, document_id):
        self.content_calls.append(document_id)
        error = self.content_error_for.get(document_id)
        if error is not None:
            raise error
        return self.contents[document_id]

    def authorize_one(self, supplied_identity="demo-credential", document_id="public-doc"):
        return authorize_document(
            supplied_identity,
            document_id,
            authenticate=self.authenticate,
            load_user_metadata=self.load_user_metadata,
            load_document_metadata=self.load_document_metadata,
            load_protected_content=self.load_protected_content,
        )

    def authorize_many(self, supplied_identity="demo-credential", document_ids=None):
        if document_ids is None:
            document_ids = ["public-doc"]
        return authorize_search(
            supplied_identity,
            document_ids,
            authenticate=self.authenticate,
            load_user_metadata=self.load_user_metadata,
            load_document_metadata=self.load_document_metadata,
            load_protected_content=self.load_protected_content,
        )


class AuthorizationBoundaryTests(unittest.TestCase):
    def test_verified_identity_and_valid_metadata_allow_access(self):
        dependencies = FakeDependencies()

        result = dependencies.authorize_one()

        self.assertIs(result.outcome, Outcome.ALLOWED)
        self.assertEqual(len(result.documents), 1)
        self.assertEqual(result.documents[0].document_id, "public-doc")
        self.assertEqual(dependencies.content_calls, ["public-doc"])

    def test_unverified_or_missing_identity_is_denied_before_content_load(self):
        cases = [
            ("not-a-credential", VerifiedIdentity("user-1", True)),
            ("demo-credential", VerifiedIdentity("user-1", False)),
            (None, VerifiedIdentity("user-1", True)),
        ]

        for supplied_identity, authentication_result in cases:
            with self.subTest(supplied_identity=supplied_identity):
                dependencies = FakeDependencies()
                dependencies.authentication_result = authentication_result

                result = dependencies.authorize_one(supplied_identity)

                self.assertIs(result.outcome, Outcome.DENIED)
                self.assertEqual(result.documents, ())
                self.assertEqual(dependencies.user_calls, 0)
                self.assertEqual(dependencies.document_calls, [])
                self.assertEqual(dependencies.content_calls, [])

    def test_missing_or_inactive_user_is_denied(self):
        for user_record in (None, {"identity": "user-1", "is_active": False,
                                  "clearance": "medium", "role": "user"}):
            with self.subTest(user_record=user_record):
                dependencies = FakeDependencies()
                dependencies.user_record = user_record

                result = dependencies.authorize_one()

                self.assertIs(result.outcome, Outcome.DENIED)
                self.assertEqual(dependencies.content_calls, [])

    def test_missing_document_is_denied(self):
        dependencies = FakeDependencies()

        result = dependencies.authorize_one(document_id="missing-doc")

        self.assertIs(result.outcome, Outcome.DENIED)
        self.assertEqual(dependencies.content_calls, [])

    def test_invalid_or_conflicting_metadata_is_denied(self):
        cases = [
            {"identity": "user-1", "is_active": True,
             "clearance": ["low", "high"], "role": "user"},
            {"identity": "someone-else", "is_active": True,
             "clearance": "medium", "role": "user"},
        ]
        for user_record in cases:
            with self.subTest(user_record=user_record):
                dependencies = FakeDependencies()
                dependencies.user_record = user_record
                result = dependencies.authorize_one()
                self.assertIs(result.outcome, Outcome.DENIED)
                self.assertEqual(dependencies.content_calls, [])

        document_cases = [
            {"sensitivity": "medium", "access_type": "unknown"},
            {"sensitivity": ["low", "high"], "access_type": "public"},
            {"sensitivity": "medium", "access_type": "department_restricted"},
        ]
        for document_record in document_cases:
            with self.subTest(document_record=document_record):
                dependencies = FakeDependencies()
                dependencies.document_records["public-doc"] = document_record
                result = dependencies.authorize_one()
                self.assertIs(result.outcome, Outcome.DENIED)
                self.assertEqual(dependencies.content_calls, [])

    def test_ordinary_policy_denial_does_not_load_candidate_content(self):
        dependencies = FakeDependencies()
        dependencies.document_records["public-doc"] = {
            "sensitivity": "high",
            "access_type": "public",
        }

        result = dependencies.authorize_one()

        self.assertIs(result.outcome, Outcome.DENIED)
        self.assertEqual(dependencies.content_calls, [])

    def test_lookup_exception_or_timeout_is_generic_dependency_failure(self):
        for error in (RuntimeError("RAW DATABASE DETAIL"), TimeoutError("RAW TIMEOUT DETAIL")):
            with self.subTest(error_type=type(error).__name__):
                dependencies = FakeDependencies()
                dependencies.document_error_for["public-doc"] = error

                result = dependencies.authorize_one()

                self.assertIs(result.outcome, Outcome.DEPENDENCY_FAILURE)
                self.assertEqual(result.documents, ())
                self.assertEqual(dependencies.content_calls, [])
                self.assertNotIn("RAW DATABASE DETAIL", repr(result))
                self.assertNotIn("RAW TIMEOUT DETAIL", repr(result))
                self.assertNotIn("PROTECTED PUBLIC CONTENT", repr(result))

    def test_multi_document_policy_denial_excludes_only_that_candidate(self):
        dependencies = FakeDependencies()
        dependencies.document_records["finance-doc"] = {
            "sensitivity": "medium",
            "access_type": "department_restricted",
            "department": "finance",
        }

        result = dependencies.authorize_many(
            document_ids=["public-doc", "finance-doc"]
        )

        self.assertIs(result.outcome, Outcome.ALLOWED)
        self.assertEqual(
            [item.document_id for item in result.documents], ["public-doc"]
        )
        self.assertEqual(dependencies.content_calls, ["public-doc"])
        self.assertNotIn("finance-doc", dependencies.content_calls)

    def test_multi_document_dependency_failure_loads_no_candidate_content(self):
        dependencies = FakeDependencies()
        dependencies.document_error_for["finance-doc"] = TimeoutError(
            "RAW FINANCE LOOKUP DETAIL"
        )

        result = dependencies.authorize_many(
            document_ids=["public-doc", "finance-doc"]
        )

        self.assertIs(result.outcome, Outcome.DEPENDENCY_FAILURE)
        self.assertEqual(result.documents, ())
        self.assertEqual(dependencies.content_calls, [])
        self.assertNotIn("RAW FINANCE LOOKUP DETAIL", repr(result))
        self.assertNotIn("PROTECTED PUBLIC CONTENT", repr(result))

    def test_content_loader_failure_does_not_return_partial_search_content(self):
        dependencies = FakeDependencies()
        dependencies.content_error_for["engineering-doc"] = RuntimeError(
            "RAW CONTENT STORE DETAIL"
        )

        result = dependencies.authorize_many(
            document_ids=["public-doc", "engineering-doc"]
        )

        self.assertIs(result.outcome, Outcome.DEPENDENCY_FAILURE)
        self.assertEqual(result.documents, ())
        self.assertEqual(dependencies.content_calls, ["public-doc", "engineering-doc"])
        self.assertNotIn("RAW CONTENT STORE DETAIL", repr(result))
        self.assertNotIn("PROTECTED PUBLIC CONTENT", repr(result))


if __name__ == "__main__":
    unittest.main()
