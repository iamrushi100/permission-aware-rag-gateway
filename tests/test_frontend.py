"""Tests for the frontend's local URL and API-response helpers."""

import unittest
from unittest.mock import patch

import httpx

from frontend import (
    FrontendError,
    SessionExpiredError,
    login_to_backend,
    search_backend,
    validate_backend_url,
)


class FrontendHelperTests(unittest.TestCase):
    def test_accepts_local_http_and_https_urls(self):
        self.assertEqual(
            validate_backend_url("http://127.0.0.1:8000/"),
            "http://127.0.0.1:8000",
        )
        self.assertEqual(
            validate_backend_url("https://localhost:8443"),
            "https://localhost:8443",
        )

    def test_rejects_nonlocal_or_unsafe_backend_urls(self):
        for url in (
            "https://example.com",
            "file:///tmp/backend",
            "http://user:pass@localhost:8000",
            "http://localhost:8000/path",
            "http://localhost:8000/?next=example.com",
        ):
            with self.subTest(url=url):
                with self.assertRaises(FrontendError):
                    validate_backend_url(url)

    @patch("frontend.httpx.post")
    def test_login_uses_existing_endpoint_and_extracts_bearer_token(self, post):
        post.return_value = httpx.Response(
            200,
            json={"access_token": "signed-demo-token", "token_type": "bearer"},
        )

        token = login_to_backend(
            "http://127.0.0.1:8000", "engineer-demo", "engineering-demo-password"
        )

        self.assertEqual(token, "signed-demo-token")
        args, kwargs = post.call_args
        self.assertEqual(args[0], "http://127.0.0.1:8000/auth/login")
        self.assertEqual(
            kwargs["json"],
            {"username": "engineer-demo", "password": "engineering-demo-password"},
        )
        self.assertFalse(kwargs["follow_redirects"])

    @patch("frontend.httpx.post")
    def test_search_sends_token_only_to_configured_local_backend(self, post):
        post.return_value = httpx.Response(
            200,
            json={
                "snippets": [{"document_id": "public-guide", "text": "Safe preview"}],
                "citations": ["public-guide"],
            },
        )

        snippets, citations = search_backend(
            "http://localhost:8000", "signed-demo-token", "demo search"
        )

        self.assertEqual(snippets, ({"document_id": "public-guide", "text": "Safe preview"},))
        self.assertEqual(citations, ("public-guide",))
        args, kwargs = post.call_args
        self.assertEqual(args[0], "http://localhost:8000/search")
        self.assertEqual(kwargs["headers"], {"Authorization": "Bearer signed-demo-token"})
        self.assertFalse(kwargs["follow_redirects"])

    @patch("frontend.httpx.post")
    def test_http_and_network_errors_are_generic(self, post):
        post.return_value = httpx.Response(401, json={"detail": "private backend detail"})
        with self.assertRaisesRegex(FrontendError, "Invalid username or password") as caught:
            login_to_backend("http://127.0.0.1:8000", "bad", "private-password")
        self.assertNotIn("private backend detail", str(caught.exception))
        self.assertNotIn("private-password", str(caught.exception))

        post.side_effect = httpx.ConnectError("private network detail")
        with self.assertRaisesRegex(FrontendError, "backend is unavailable") as caught:
            search_backend("http://127.0.0.1:8000", "private-token", "query")
        self.assertNotIn("private network detail", str(caught.exception))
        self.assertNotIn("private-token", str(caught.exception))

    @patch("frontend.httpx.post")
    def test_expired_search_token_has_a_safe_specific_error(self, post):
        post.return_value = httpx.Response(401, json={"detail": "private detail"})
        with self.assertRaises(SessionExpiredError) as caught:
            search_backend("http://127.0.0.1:8000", "private-token", "query")
        self.assertIn("log in again", str(caught.exception))
        self.assertNotIn("private detail", str(caught.exception))
        self.assertNotIn("private-token", str(caught.exception))

    @patch("frontend.httpx.post")
    def test_malformed_success_response_is_not_displayed_or_returned(self, post):
        post.return_value = httpx.Response(
            200,
            json={
                "snippets": [{"document_id": "secret-id", "text": "PRIVATE TEXT"}],
                "citations": ["different-id"],
                "debug": "private diagnostic",
            },
        )

        with self.assertRaises(FrontendError) as caught:
            search_backend("http://127.0.0.1:8000", "token", "query")
        self.assertNotIn("PRIVATE TEXT", str(caught.exception))
        self.assertNotIn("private diagnostic", str(caught.exception))

    @patch("frontend.httpx.post")
    def test_http_redirects_are_not_followed(self, post):
        post.return_value = httpx.Response(302, headers={"Location": "http://example.com"})
        with self.assertRaises(FrontendError):
            login_to_backend("http://127.0.0.1:8000", "user", "password")
        self.assertFalse(post.call_args.kwargs["follow_redirects"])


if __name__ == "__main__":
    unittest.main()
