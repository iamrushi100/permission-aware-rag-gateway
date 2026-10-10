"""Local API tests for signed tokens and authorized response delivery."""

import io
import unittest
from contextlib import redirect_stderr, redirect_stdout
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

import jwt
from fastapi.testclient import TestClient

from api import (
    DEMO_ACCOUNTS,
    TOKEN_AUDIENCE,
    TOKEN_ISSUER,
    create_app,
)


TEST_SECRET = "test-signing-secret-that-is-at-least-32-bytes"
ENGINEER_LOGIN = {
    "username": "engineer-demo",
    "password": "engineering-demo-password",
}


class ApiTests(unittest.TestCase):
    def setUp(self):
        self.app = create_app(secret_key=TEST_SECRET)
        self.client = TestClient(self.app)

    def tearDown(self):
        self.client.close()

    def login_and_get_token(self):
        response = self.client.post("/auth/login", json=ENGINEER_LOGIN)
        self.assertEqual(response.status_code, 200)
        return response.json()["access_token"]

    def signed_token(self, claims, secret=TEST_SECRET):
        return jwt.encode(claims, secret, algorithm="HS256")

    def default_claims(self, *, subject="demo-user", expiry=None):
        now = datetime.now(timezone.utc)
        return {
            "sub": subject,
            "iat": now,
            "exp": expiry or now + timedelta(minutes=5),
            "iss": TOKEN_ISSUER,
            "aud": TOKEN_AUDIENCE,
        }

    def test_valid_login_token_reaches_authorized_search_boundary(self):
        token = self.login_and_get_token()

        response = self.client.post(
            "/search",
            json={"query": "demo search"},
            headers={"Authorization": f"Bearer {token}"},
        )

        self.assertEqual(response.status_code, 200)
        body = response.json()
        self.assertEqual(
            body["citations"], ["public-guide", "engineering-guide"]
        )
        serialized = response.text
        self.assertIn("FICTIONAL PUBLIC GUIDE CONTENT", serialized)
        self.assertIn("FICTIONAL ENGINEERING CONTENT", serialized)
        self.assertNotIn("FICTIONAL FINANCE SECRET CONTENT", serialized)
        self.assertNotIn("finance-plan", serialized)

    def test_invalid_login_credentials_return_generic_authentication_failure(self):
        response = self.client.post(
            "/auth/login",
            json={"username": "engineer-demo", "password": "wrong-password"},
        )

        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.json(), {"detail": "Authentication failed"})
        self.assertNotIn("wrong-password", response.text)
        self.assertNotIn("access_token", response.text)

    def test_missing_bearer_token_is_rejected(self):
        response = self.client.post("/search", json={"query": "demo search"})

        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.json(), {"detail": "Authentication failed"})
        self.assertEqual(self.app.state.dependencies.user_calls, 0)
        self.assertEqual(self.app.state.dependencies.document_calls, [])
        self.assertEqual(self.app.state.dependencies.content_calls, [])

    def test_malformed_token_is_rejected_generically(self):
        response = self.client.post(
            "/search",
            json={"query": "demo search"},
            headers={"Authorization": "Bearer not-a-signed-token"},
        )

        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.json(), {"detail": "Authentication failed"})
        self.assertNotIn("not-a-signed-token", response.text)
        self.assertEqual(self.app.state.dependencies.user_calls, 0)
        self.assertEqual(self.app.state.dependencies.document_calls, [])
        self.assertEqual(self.app.state.dependencies.content_calls, [])

    def test_forged_signature_is_rejected(self):
        token = self.signed_token(
            self.default_claims(), secret="different-test-secret-with-32-bytes"
        )

        response = self.client.post(
            "/search",
            json={"query": "demo search"},
            headers={"Authorization": f"Bearer {token}"},
        )

        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.json(), {"detail": "Authentication failed"})
        self.assertEqual(self.app.state.dependencies.content_calls, [])

    def test_expired_token_is_rejected(self):
        expired_at = datetime.now(timezone.utc) - timedelta(minutes=1)
        token = self.signed_token(self.default_claims(expiry=expired_at))

        response = self.client.post(
            "/search",
            json={"query": "demo search"},
            headers={"Authorization": f"Bearer {token}"},
        )

        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.json(), {"detail": "Authentication failed"})
        self.assertEqual(self.app.state.dependencies.content_calls, [])

    def test_token_missing_required_claim_is_rejected(self):
        claims = self.default_claims()
        del claims["aud"]
        token = self.signed_token(claims)

        response = self.client.post(
            "/search",
            json={"query": "demo search"},
            headers={"Authorization": f"Bearer {token}"},
        )

        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.json(), {"detail": "Authentication failed"})
        self.assertEqual(self.app.state.dependencies.content_calls, [])

    def test_token_with_wrong_issuer_is_rejected(self):
        claims = self.default_claims()
        claims["iss"] = "untrusted-demo-issuer"
        token = self.signed_token(claims)

        response = self.client.post(
            "/search",
            json={"query": "demo search"},
            headers={"Authorization": f"Bearer {token}"},
        )

        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.json(), {"detail": "Authentication failed"})
        self.assertNotIn("FICTIONAL PUBLIC GUIDE CONTENT", response.text)
        self.assertNotIn("FICTIONAL FINANCE SECRET CONTENT", response.text)
        self.assertEqual(self.app.state.dependencies.content_calls, [])

    def test_token_with_wrong_audience_is_rejected(self):
        claims = self.default_claims()
        claims["aud"] = "untrusted-demo-client"
        token = self.signed_token(claims)

        response = self.client.post(
            "/search",
            json={"query": "demo search"},
            headers={"Authorization": f"Bearer {token}"},
        )

        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.json(), {"detail": "Authentication failed"})
        self.assertNotIn("FICTIONAL PUBLIC GUIDE CONTENT", response.text)
        self.assertNotIn("FICTIONAL FINANCE SECRET CONTENT", response.text)
        self.assertEqual(self.app.state.dependencies.content_calls, [])

    def test_search_rejects_client_supplied_privilege_fields(self):
        token = self.login_and_get_token()

        response = self.client.post(
            "/search",
            json={"query": "demo search", "role": "admin", "clearance": "high"},
            headers={"Authorization": f"Bearer {token}"},
        )

        self.assertEqual(response.status_code, 422)
        self.assertEqual(response.json(), {"detail": "Invalid request"})
        self.assertEqual(self.app.state.dependencies.content_calls, [])

    def test_denied_document_is_not_returned_or_loaded(self):
        token = self.login_and_get_token()

        response = self.client.post(
            "/search",
            json={"query": "finance only"},
            headers={"Authorization": f"Bearer {token}"},
        )

        self.assertEqual(response.status_code, 403)
        self.assertEqual(response.json(), {"detail": "Request denied"})
        self.assertNotIn("FICTIONAL FINANCE SECRET CONTENT", response.text)
        self.assertNotIn("finance-plan", response.text)
        self.assertEqual(self.app.state.dependencies.content_calls, [])

    def test_authorized_search_records_content_free_audit_event(self):
        token = self.login_and_get_token()

        response = self.client.post(
            "/search",
            json={"query": "demo search"},
            headers={"Authorization": f"Bearer {token}"},
        )

        self.assertEqual(response.status_code, 200)
        events = self.app.state.audit_sink.events
        self.assertEqual(len(events), 1)
        event = events[0]
        self.assertEqual(event.action, "search")
        self.assertEqual(event.outcome, "allowed")
        self.assertEqual(event.subject, "demo-user")
        self.assertEqual(event.timestamp_utc.utcoffset(), timedelta(0))
        self.assertEqual(
            set(event.__dataclass_fields__),
            {"timestamp_utc", "action", "outcome", "subject"},
        )
        event_text = repr(event)
        for sensitive_value in (
            ENGINEER_LOGIN["password"],
            token,
            f"Bearer {token}",
            TEST_SECRET,
            "demo search",
            "FICTIONAL PUBLIC GUIDE CONTENT",
            "FICTIONAL ENGINEERING CONTENT",
        ):
            self.assertNotIn(sensitive_value, event_text)

    def test_denied_search_records_generic_denial_event(self):
        token = self.login_and_get_token()

        response = self.client.post(
            "/search",
            json={"query": "finance only"},
            headers={"Authorization": f"Bearer {token}"},
        )

        self.assertEqual(response.status_code, 403)
        self.assertEqual(len(self.app.state.audit_sink.events), 1)
        event = self.app.state.audit_sink.events[0]
        self.assertEqual(
            (event.action, event.outcome, event.subject),
            ("search", "denied", "demo-user"),
        )
        self.assertNotIn("finance-plan", repr(event))
        self.assertNotIn("FICTIONAL FINANCE SECRET CONTENT", repr(event))

    def test_dependency_failure_records_generic_failure_event(self):
        token = self.login_and_get_token()
        raw_error = "RAW DATABASE FAILURE SECRET CONTENT"
        self.app.state.dependencies.document_errors["dependency-doc"] = RuntimeError(
            raw_error
        )

        response = self.client.post(
            "/search",
            json={"query": "dependency failure"},
            headers={"Authorization": f"Bearer {token}"},
        )

        self.assertEqual(response.status_code, 503)
        self.assertEqual(response.json(), {"detail": "Request unavailable"})
        self.assertEqual(len(self.app.state.audit_sink.events), 1)
        event = self.app.state.audit_sink.events[0]
        self.assertEqual(event.outcome, "dependency_failure")
        self.assertNotIn(raw_error, repr(event) + response.text)
        self.assertNotIn("FICTIONAL DEPENDENCY CONTENT", repr(event) + response.text)

    def test_audit_sink_failure_does_not_turn_denial_into_success_or_leak_details(self):
        class FailingAuditSink:
            def emit(self, event):
                raise RuntimeError("RAW AUDIT FAILURE FINANCE SECRET CONTENT")

        token = self.login_and_get_token()
        self.app.state.audit_sink = FailingAuditSink()
        captured = io.StringIO()

        with redirect_stdout(captured), redirect_stderr(captured):
            response = self.client.post(
                "/search",
                json={"query": "finance only"},
                headers={"Authorization": f"Bearer {token}"},
            )

        self.assertEqual(response.status_code, 403)
        self.assertEqual(response.json(), {"detail": "Request denied"})
        self.assertNotIn("RAW AUDIT FAILURE", response.text + captured.getvalue())
        self.assertNotIn(
            "FICTIONAL FINANCE SECRET CONTENT", response.text + captured.getvalue()
        )
        self.assertEqual(self.app.state.dependencies.content_calls, [])

    def test_token_is_denied_if_server_side_user_becomes_inactive(self):
        token = self.login_and_get_token()
        account = DEMO_ACCOUNTS["engineer-demo"]
        inactive_account = replace(
            account,
            user_record={**account.user_record, "is_active": False},
        )

        # The token was issued while the account was active. The lookup used by
        # authorization must still honor the account's current server record.
        with patch.dict(DEMO_ACCOUNTS, {"engineer-demo": inactive_account}):
            response = self.client.post(
                "/search",
                json={"query": "demo search"},
                headers={"Authorization": f"Bearer {token}"},
            )

        self.assertEqual(response.status_code, 403)
        self.assertEqual(response.json(), {"detail": "Request denied"})
        self.assertNotIn("FICTIONAL", response.text)
        self.assertEqual(self.app.state.dependencies.content_calls, [])

    def test_signed_privilege_claims_do_not_override_server_side_metadata(self):
        claims = self.default_claims()
        claims.update({"role": "admin", "clearance": "high", "department": "finance"})
        token = self.signed_token(claims)

        response = self.client.post(
            "/search",
            json={"query": "finance only"},
            headers={"Authorization": f"Bearer {token}"},
        )

        self.assertEqual(response.status_code, 403)
        self.assertEqual(response.json(), {"detail": "Request denied"})
        self.assertNotIn("FICTIONAL FINANCE SECRET CONTENT", response.text)
        self.assertNotIn("finance-plan", response.text)
        self.assertEqual(self.app.state.dependencies.content_calls, [])

    def test_metadata_failure_returns_generic_response_without_loading_content(self):
        token = self.login_and_get_token()
        self.app.state.dependencies.document_errors["dependency-doc"] = RuntimeError(
            "RAW DATABASE DETAIL FICTIONAL PUBLIC GUIDE CONTENT"
        )

        response = self.client.post(
            "/search",
            json={"query": "dependency failure"},
            headers={"Authorization": f"Bearer {token}"},
        )

        self.assertEqual(response.status_code, 503)
        self.assertEqual(response.json(), {"detail": "Request unavailable"})
        self.assertNotIn("RAW DATABASE DETAIL", response.text)
        self.assertNotIn("FICTIONAL PUBLIC GUIDE CONTENT", response.text)
        self.assertEqual(self.app.state.dependencies.content_calls, [])

    def test_missing_signing_secret_fails_safely(self):
        with patch.dict("os.environ", {"RAG_GATEWAY_SECRET": ""}):
            client = TestClient(create_app())
        try:
            response = client.post("/auth/login", json=ENGINEER_LOGIN)
        finally:
            client.close()

        self.assertEqual(response.status_code, 503)
        self.assertEqual(response.json(), {"detail": "Service unavailable"})
        self.assertNotIn("engineering-demo-password", response.text)

    def test_short_signing_secret_cannot_issue_token(self):
        client = TestClient(create_app(secret_key="too-short"))
        try:
            response = client.post("/auth/login", json=ENGINEER_LOGIN)
        finally:
            client.close()

        self.assertEqual(response.status_code, 503)
        self.assertEqual(response.json(), {"detail": "Service unavailable"})
        self.assertNotIn("engineering-demo-password", response.text)
        self.assertNotIn("access_token", response.text)

    def test_user_metadata_failure_does_not_leak_details(self):
        token = self.login_and_get_token()
        self.app.state.dependencies.user_errors["demo-user"] = RuntimeError(
            "RAW USER STORE DETAIL"
        )

        response = self.client.post(
            "/search",
            json={"query": "demo search"},
            headers={"Authorization": f"Bearer {token}"},
        )

        self.assertEqual(response.status_code, 503)
        self.assertEqual(response.json(), {"detail": "Request unavailable"})
        self.assertNotIn("RAW USER STORE DETAIL", response.text)
        self.assertNotIn("FICTIONAL PUBLIC GUIDE CONTENT", response.text)
        self.assertEqual(self.app.state.dependencies.content_calls, [])


if __name__ == "__main__":
    unittest.main()
