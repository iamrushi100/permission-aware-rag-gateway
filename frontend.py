"""Small Streamlit client for the local Permission-Aware RAG API."""

from __future__ import annotations

from typing import Any
from urllib.parse import urlsplit

import httpx


REQUEST_TIMEOUT_SECONDS = 5.0
_LOCAL_HOSTS = {"localhost", "127.0.0.1", "::1"}


class FrontendError(Exception):
    """An error with a safe, user-facing message and no backend details."""


class SessionExpiredError(FrontendError):
    """The bearer token was rejected and must be cleared from the session."""


def validate_backend_url(value: object) -> str:
    """Return a normalized local backend URL or raise a generic safe error."""

    if type(value) is not str or not value.strip():
        raise FrontendError("Enter a local backend URL.")

    try:
        parsed = urlsplit(value.strip())
        host = parsed.hostname
        port = parsed.port
    except ValueError:
        raise FrontendError("Use a valid local HTTP or HTTPS URL.") from None

    if (
        parsed.scheme.lower() not in {"http", "https"}
        or host not in _LOCAL_HOSTS
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path not in {"", "/"}
        or parsed.query
        or parsed.fragment
        or (port is not None and not 1 <= port <= 65535)
    ):
        raise FrontendError("Use a local HTTP or HTTPS backend URL only.")

    return f"{parsed.scheme.lower()}://{parsed.netloc}".rstrip("/")


def _response_json(response: httpx.Response) -> Any:
    try:
        return response.json()
    except (ValueError, TypeError):
        raise FrontendError("The backend returned an unexpected response.") from None


def _check_http_status(response: httpx.Response, *, operation: str) -> None:
    if response.status_code == 200:
        return
    if response.status_code == 401:
        if operation == "login":
            raise FrontendError("Invalid username or password.")
        raise SessionExpiredError(
            "Your session is invalid or expired. Please log in again."
        )
    if response.status_code == 403:
        raise FrontendError("Access denied for this search.")
    if response.status_code >= 500:
        raise FrontendError("The backend is unavailable. Check that it is running.")
    raise FrontendError(f"The request could not be completed (HTTP {response.status_code}).")


def login_to_backend(backend_url: object, username: str, password: str) -> str:
    """Authenticate through the API and return its bearer token."""

    base_url = validate_backend_url(backend_url)
    try:
        response = httpx.post(
            f"{base_url}/auth/login",
            json={"username": username, "password": password},
            timeout=REQUEST_TIMEOUT_SECONDS,
            follow_redirects=False,
        )
    except httpx.HTTPError:
        raise FrontendError("The backend is unavailable. Check the URL and try again.") from None

    _check_http_status(response, operation="login")
    body = _response_json(response)
    if (
        type(body) is not dict
        or type(body.get("access_token")) is not str
        or not body["access_token"].strip()
        or body["access_token"].strip() != body["access_token"]
        or type(body.get("token_type")) is not str
        or body["token_type"].lower() != "bearer"
    ):
        raise FrontendError("The backend returned an unexpected response.")
    return body["access_token"]


def search_backend(
    backend_url: object, token: str, query: str
) -> tuple[tuple[dict[str, str], ...], tuple[str, ...]]:
    """Return only validated snippet and citation fields from the API."""

    base_url = validate_backend_url(backend_url)
    if type(token) is not str or not token.strip():
        raise FrontendError("Log in before searching.")

    try:
        response = httpx.post(
            f"{base_url}/search",
            json={"query": query},
            headers={"Authorization": f"Bearer {token}"},
            timeout=REQUEST_TIMEOUT_SECONDS,
            follow_redirects=False,
        )
    except httpx.HTTPError:
        raise FrontendError("The backend is unavailable. Check the URL and try again.") from None

    _check_http_status(response, operation="search")
    body = _response_json(response)
    if type(body) is not dict:
        raise FrontendError("The backend returned an unexpected response.")

    raw_snippets = body.get("snippets")
    raw_citations = body.get("citations")
    if type(raw_snippets) is not list or type(raw_citations) is not list:
        raise FrontendError("The backend returned an unexpected response.")

    snippets: list[dict[str, str]] = []
    for item in raw_snippets:
        if (
            type(item) is not dict
            or type(item.get("document_id")) is not str
            or not item["document_id"].strip()
            or type(item.get("text")) is not str
            or not item["text"].strip()
        ):
            raise FrontendError("The backend returned an unexpected response.")
        snippets.append({"document_id": item["document_id"], "text": item["text"]})

    citations = tuple(raw_citations)
    if (
        any(type(citation) is not str or not citation.strip() for citation in citations)
        or citations != tuple(item["document_id"] for item in snippets)
    ):
        raise FrontendError("The backend returned an unexpected response.")

    return tuple(snippets), citations


def main() -> None:
    """Render the local-only search interface."""

    import streamlit as st

    st.set_page_config(
        page_title="Permission-Aware RAG Gateway",
        layout="centered",
    )
    st.title("Permission-Aware RAG Security Gateway")
    st.caption(
        "A local security prototype. The backend makes every authentication and access decision."
    )

    if "backend_url" not in st.session_state:
        st.session_state.backend_url = "http://127.0.0.1:8000"
    backend_url = st.text_input(
        "Backend URL",
        value=st.session_state.backend_url,
        help="For this demo, only localhost, 127.0.0.1, or ::1 URLs are accepted.",
    )
    st.session_state.backend_url = backend_url

    try:
        normalized_url = validate_backend_url(backend_url)
    except FrontendError as error:
        normalized_url = None
        st.error(str(error))

    notice = st.session_state.pop("ui_notice", None)
    if notice:
        st.error(notice)

    # A token is bound to the backend URL where login occurred. Changing the
    # URL clears it, so it cannot be forwarded to another configured host.
    if st.session_state.get("gateway_token") and (
        normalized_url is None
        or st.session_state.get("token_backend_url") != normalized_url
    ):
        st.session_state.pop("gateway_token", None)
        st.session_state.pop("token_backend_url", None)
        st.info("Backend URL changed. Please log in again.")

    token = st.session_state.get("gateway_token")
    if token is None:
        st.subheader("Sign in")
        with st.form("login_form"):
            username = st.text_input("Username")
            password = st.text_input("Password", type="password")
            login_submitted = st.form_submit_button("Log in", disabled=normalized_url is None)

        if login_submitted:
            try:
                token = login_to_backend(normalized_url, username, password)
                st.session_state.gateway_token = token
                st.session_state.token_backend_url = normalized_url
                st.success("Signed in. Your token is held in this browser session only.")
                st.rerun()
            except FrontendError as error:
                st.error(str(error))
    else:
        left, right = st.columns([4, 1])
        left.subheader("Search documents")
        if right.button("Log out", use_container_width=True):
            st.session_state.pop("gateway_token", None)
            st.session_state.pop("token_backend_url", None)
            st.rerun()

        with st.form("search_form"):
            query = st.text_input("Search query", max_chars=200)
            search_submitted = st.form_submit_button("Search", disabled=normalized_url is None)

        if search_submitted:
            if not query.strip():
                st.warning("Enter a search query.")
            else:
                try:
                    snippets, citations = search_backend(
                        normalized_url,
                        st.session_state.gateway_token,
                        query,
                    )
                    if not snippets:
                        st.info("No authorized documents matched this search.")
                    else:
                        st.success(f"Found {len(snippets)} authorized document(s).")
                        for snippet in snippets:
                            with st.container(border=True):
                                st.text(f"Document ID: {snippet['document_id']}")
                                st.text(snippet["text"])
                        st.markdown("**Citations**")
                        st.text(" | ".join(citations))
                except SessionExpiredError as error:
                    st.session_state.pop("gateway_token", None)
                    st.session_state.pop("token_backend_url", None)
                    st.session_state.ui_notice = str(error)
                    st.rerun()
                except FrontendError as error:
                    st.error(str(error))

    st.divider()
    st.caption(
        "Fictional in-memory data | local JWT demo | no real LLM | not for production use"
    )


if __name__ == "__main__":
    main()
