"""Local FastAPI demo with signed-token authentication and protected search."""

from __future__ import annotations

import hashlib
import hmac
import os
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

import jwt
from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jwt.exceptions import InvalidTokenError
from pydantic import BaseModel, ConfigDict, Field

from authorization_boundary import Outcome, VerifiedIdentity
from response_boundary import search_and_preview
from retrieval_boundary import InMemoryCandidateProvider


SECRET_ENVIRONMENT_VARIABLE = "RAG_GATEWAY_SECRET"
TOKEN_ISSUER = "permission-aware-rag-local-demo"
TOKEN_AUDIENCE = "permission-aware-rag-demo-client"
TOKEN_LIFETIME = timedelta(minutes=15)
PASSWORD_HASH_ITERATIONS = 200_000
JWT_ALGORITHM = "HS256"


@dataclass(frozen=True)
class DemoAccount:
    """Server-side demo login material and canonical user metadata."""

    subject: str
    password_salt: bytes
    password_digest: bytes
    user_record: dict[str, object]


def _digest_password(password: str, salt: bytes) -> bytes:
    """Hash a demo password with the Python standard library."""

    return hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        PASSWORD_HASH_ITERATIONS,
    )


# These fixed accounts and salts are fictional, local-demo-only values.
# Passwords are stored as PBKDF2 digests rather than plaintext.
DEMO_ACCOUNTS = {
    "engineer-demo": DemoAccount(
        subject="demo-user",
        password_salt=b"engineering-demo-salt-v1",
        password_digest=bytes.fromhex(
            "9efbd9c3d613f36dc7a24c0cb7fe7cb8058b171d0ee592a8ce0b60ba2a2a750b"
        ),
        user_record={
            "identity": "demo-user",
            "is_active": True,
            "clearance": "medium",
            "role": "user",
            "department": "engineering",
        },
    ),
    "finance-demo": DemoAccount(
        subject="finance-user",
        password_salt=b"finance-demo-salt-v1",
        password_digest=bytes.fromhex(
            "b4262f71d455a97a01a41e996807b817232fa58b60cab0d389bf5e7034e5b652"
        ),
        user_record={
            "identity": "finance-user",
            "is_active": True,
            "clearance": "medium",
            "role": "user",
            "department": "finance",
        },
    ),
}

_DUMMY_SALT = b"unknown-account-demo-salt"
_DUMMY_DIGEST = _digest_password("not-a-real-password", _DUMMY_SALT)


class LoginRequest(BaseModel):
    """Login fields only; authorization attributes are never accepted here."""

    model_config = ConfigDict(extra="forbid")

    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=1, max_length=128)


class SearchRequest(BaseModel):
    """The search endpoint accepts a query, not caller-supplied identity data."""

    model_config = ConfigDict(extra="forbid")

    query: str = Field(min_length=1, max_length=200)


class LoginResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"


class DemoDependencies:
    """Fictional in-memory user, document, and content records for this API."""

    def __init__(self):
        self.user_calls = 0
        self.document_calls: list[str] = []
        self.user_errors: dict[str, Exception] = {}
        self.document_errors: dict[str, Exception] = {}
        self.content_errors: dict[str, Exception] = {}
        self.document_records = {
            "public-guide": {"sensitivity": "low", "access_type": "public"},
            "engineering-guide": {
                "sensitivity": "medium",
                "access_type": "department_restricted",
                "department": "engineering",
            },
            "finance-plan": {
                "sensitivity": "medium",
                "access_type": "department_restricted",
                "department": "finance",
            },
            "dependency-doc": {"sensitivity": "low", "access_type": "public"},
        }
        self.protected_contents = {
            "public-guide": "FICTIONAL PUBLIC GUIDE CONTENT",
            "engineering-guide": "FICTIONAL ENGINEERING CONTENT",
            "finance-plan": "FICTIONAL FINANCE SECRET CONTENT",
            "dependency-doc": "FICTIONAL DEPENDENCY CONTENT",
        }
        self.content_calls: list[str] = []

    def load_user_metadata(self, subject: str) -> dict[str, object] | None:
        self.user_calls += 1
        error = self.user_errors.get(subject)
        if error is not None:
            raise error
        for account in DEMO_ACCOUNTS.values():
            if account.subject == subject:
                return dict(account.user_record)
        return None

    def load_document_metadata(self, document_id: str) -> dict[str, object] | None:
        self.document_calls.append(document_id)
        error = self.document_errors.get(document_id)
        if error is not None:
            raise error
        record = self.document_records.get(document_id)
        return None if record is None else dict(record)

    def load_protected_content(self, document_id: str) -> str:
        self.content_calls.append(document_id)
        error = self.content_errors.get(document_id)
        if error is not None:
            raise error
        return self.protected_contents[document_id]


def _secret_is_usable(secret: object) -> bool:
    return type(secret) is str and len(secret.encode("utf-8")) >= 32


def _generic_authentication_failure() -> HTTPException:
    return HTTPException(
        status_code=401,
        detail="Authentication failed",
        headers={"WWW-Authenticate": "Bearer"},
    )


def create_app(secret_key: str | None = None) -> FastAPI:
    """Build the local API; secret_key is injectable for deterministic tests."""

    app = FastAPI(
        title="Permission-Aware RAG Security Gateway (local demo)",
        description="A local prototype; not production authentication or RAG.",
        debug=False,
    )
    app.state.signing_secret = (
        secret_key
        if secret_key is not None
        else os.environ.get(SECRET_ENVIRONMENT_VARIABLE)
    )
    app.state.dependencies = DemoDependencies()
    app.state.candidate_provider = InMemoryCandidateProvider(
        {
            "demo search": ("public-guide", "engineering-guide", "finance-plan"),
            "finance only": ("finance-plan",),
            "dependency failure": ("public-guide", "dependency-doc"),
        }
    )

    bearer_scheme = HTTPBearer(auto_error=False)

    def configured_secret() -> str:
        secret = app.state.signing_secret
        if not _secret_is_usable(secret):
            raise HTTPException(status_code=503, detail="Service unavailable")
        return secret

    def verified_identity(
        request: Request,
        credentials: HTTPAuthorizationCredentials | None = Depends(bearer_scheme),
    ) -> VerifiedIdentity:
        secret = request.app.state.signing_secret
        if not _secret_is_usable(secret):
            raise HTTPException(status_code=503, detail="Service unavailable")
        if credentials is None or credentials.scheme.lower() != "bearer":
            raise _generic_authentication_failure()

        try:
            claims = jwt.decode(
                credentials.credentials,
                secret,
                algorithms=[JWT_ALGORITHM],
                issuer=TOKEN_ISSUER,
                audience=TOKEN_AUDIENCE,
                options={"require": ["sub", "exp", "iat", "iss", "aud"]},
            )
        except InvalidTokenError:
            raise _generic_authentication_failure() from None

        subject = claims.get("sub")
        if type(subject) is not str or not subject.strip():
            raise _generic_authentication_failure()
        if not any(account.subject == subject for account in DEMO_ACCOUNTS.values()):
            raise _generic_authentication_failure()

        # This trusted marker is created only after token signature and claims
        # validation. It is never accepted from request data.
        return VerifiedIdentity(subject=subject, verified=True)

    @app.exception_handler(RequestValidationError)
    async def safe_validation_error(
        _request: Request, _exception: RequestValidationError
    ) -> JSONResponse:
        # Pydantic validation errors may contain submitted values such as passwords.
        return JSONResponse(status_code=422, content={"detail": "Invalid request"})

    @app.exception_handler(Exception)
    async def safe_unexpected_error(_request: Request, _exception: Exception) -> JSONResponse:
        return JSONResponse(status_code=500, content={"detail": "Request failed"})

    @app.post("/auth/login", response_model=LoginResponse)
    def login(body: LoginRequest) -> LoginResponse:
        secret = configured_secret()
        account = DEMO_ACCOUNTS.get(body.username)
        salt = account.password_salt if account is not None else _DUMMY_SALT
        expected = account.password_digest if account is not None else _DUMMY_DIGEST
        supplied = _digest_password(body.password, salt)
        if account is None or not hmac.compare_digest(supplied, expected):
            raise _generic_authentication_failure()
        if account.user_record.get("is_active") is not True:
            raise _generic_authentication_failure()

        now = datetime.now(timezone.utc)
        token = jwt.encode(
            {
                "sub": account.subject,
                "iat": now,
                "exp": now + TOKEN_LIFETIME,
                "iss": TOKEN_ISSUER,
                "aud": TOKEN_AUDIENCE,
            },
            secret,
            algorithm=JWT_ALGORITHM,
        )
        # Returning the token here is necessary for login; it is never logged
        # or included in errors or protected-search responses.
        return LoginResponse(access_token=token)

    @app.post("/search")
    def search(
        body: SearchRequest,
        request: Request,
        identity: VerifiedIdentity = Depends(verified_identity),
    ) -> dict[str, object]:
        dependencies: DemoDependencies = request.app.state.dependencies

        def authenticate(subject: object) -> VerifiedIdentity | None:
            if subject == identity.subject:
                return identity
            return None

        preview = search_and_preview(
            body.query,
            identity.subject,
            candidate_provider=request.app.state.candidate_provider,
            authenticate=authenticate,
            load_user_metadata=dependencies.load_user_metadata,
            load_document_metadata=dependencies.load_document_metadata,
            load_protected_content=dependencies.load_protected_content,
        )
        if preview.outcome is Outcome.DENIED:
            raise HTTPException(status_code=403, detail="Request denied")
        if preview.outcome is not Outcome.ALLOWED:
            raise HTTPException(status_code=503, detail="Request unavailable")

        return {
            "snippets": [
                {"document_id": item.document_id, "text": item.text}
                for item in preview.snippets
            ],
            "citations": list(preview.citations),
        }

    return app


app = create_app()
