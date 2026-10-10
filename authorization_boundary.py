"""Small boundary around the pure authorization policy.

This module passes an identity supplied by a trusted authentication adapter
and canonical metadata to ``is_authorized`` before loading protected content.
The boundary itself does not verify tokens. Tests use a simulated identity;
the local API constructs ``VerifiedIdentity`` only after signed-token checks.
Neither path provides production authentication.
"""

from dataclasses import dataclass
from enum import Enum
from typing import Callable, Iterable

from authorization import AccessType, Clearance, Document, User, UserRole, is_authorized


class Outcome(Enum):
    """Safe, generic result categories returned by the boundary."""

    ALLOWED = "allowed"
    DENIED = "denied"
    DEPENDENCY_FAILURE = "dependency_failure"


@dataclass(frozen=True)
class VerifiedIdentity:
    """Server-created identity marker; this data type does not verify tokens."""

    subject: str
    verified: bool


@dataclass(frozen=True)
class AuthorizedContent:
    """Protected content that was loaded after its document was authorized."""

    document_id: str
    content: object


@dataclass(frozen=True)
class BoundaryResult:
    """Generic outcome; documents are present only for an allowed result."""

    outcome: Outcome
    documents: tuple[AuthorizedContent, ...] = ()


def _result(outcome: Outcome) -> BoundaryResult:
    """Create a result without exception details or partially loaded content."""

    return BoundaryResult(outcome=outcome)


def _non_empty_text(value: object) -> bool:
    return type(value) is str and bool(value.strip())


def _has_expected_fields(
    record: object,
    required: set[str],
    optional: set[str],
) -> bool:
    """Accept only a plain dictionary with a known, non-conflicting shape."""

    if type(record) is not dict:
        return False
    if any(type(key) is not str for key in record):
        return False
    keys = set(record)
    return required.issubset(keys) and keys.issubset(required | optional)


def _parse_clearance(value: object) -> Clearance | None:
    """Convert one recognized scalar metadata value to its clearance enum."""

    if type(value) is not str:
        return None
    return {
        "low": Clearance.LOW,
        "medium": Clearance.MEDIUM,
        "high": Clearance.HIGH,
    }.get(value)


def _parse_user(record: object, identity: VerifiedIdentity) -> User | None:
    required = {"identity", "is_active", "clearance", "role"}
    optional = {"department"}
    if not _has_expected_fields(record, required, optional):
        return None

    if not _non_empty_text(record["identity"]):
        return None
    # A different identity in the user record conflicts with the verified one.
    if record["identity"] != identity.subject:
        return None
    if type(record["is_active"]) is not bool:
        return None

    clearance = _parse_clearance(record["clearance"])
    if clearance is None:
        return None

    roles = {
        "user": UserRole.USER,
        "administrator": UserRole.ADMINISTRATOR,
    }
    raw_role = record["role"]
    if type(raw_role) is not str or raw_role not in roles:
        return None

    department = record.get("department")
    if department is not None and not _non_empty_text(department):
        return None

    return User(
        identity=identity.subject,
        is_authenticated=True,
        is_active=record["is_active"],
        clearance=clearance,
        role=roles[raw_role],
        department=department,
    )


def _parse_document(record: object) -> Document | None:
    required = {"sensitivity", "access_type"}
    optional = {"department"}
    if not _has_expected_fields(record, required, optional):
        return None

    sensitivity = _parse_clearance(record["sensitivity"])
    if sensitivity is None:
        return None

    access_types = {
        "public": AccessType.PUBLIC,
        "department_restricted": AccessType.DEPARTMENT_RESTRICTED,
    }
    raw_access_type = record["access_type"]
    if type(raw_access_type) is not str or raw_access_type not in access_types:
        return None

    department = record.get("department")
    if department is not None and not _non_empty_text(department):
        return None

    return Document(
        sensitivity=sensitivity,
        access_type=access_types[raw_access_type],
        department=department,
    )


def _verified_user(
    supplied_identity: object,
    authenticate: Callable[[object], object],
    load_user_metadata: Callable[[str], object],
) -> tuple[Outcome, VerifiedIdentity | None, User | None]:
    """Simulate identity verification and load/validate the user's metadata."""

    if not _non_empty_text(supplied_identity):
        return Outcome.DENIED, None, None

    try:
        identity = authenticate(supplied_identity)
    except Exception:
        return Outcome.DEPENDENCY_FAILURE, None, None

    if type(identity) is not VerifiedIdentity:
        return Outcome.DENIED, None, None
    if identity.verified is not True or not _non_empty_text(identity.subject):
        return Outcome.DENIED, None, None

    try:
        user_record = load_user_metadata(identity.subject)
    except Exception:
        return Outcome.DEPENDENCY_FAILURE, None, None

    if user_record is None:
        return Outcome.DENIED, None, None

    user = _parse_user(user_record, identity)
    if user is None or not user.is_active:
        return Outcome.DENIED, None, None

    return Outcome.ALLOWED, identity, user


def authorize_document(
    supplied_identity: object,
    document_id: object,
    *,
    authenticate: Callable[[object], object],
    load_user_metadata: Callable[[str], object],
    load_document_metadata: Callable[[str], object],
    load_protected_content: Callable[[str], object],
) -> BoundaryResult:
    """Authorize one document, then and only then load its protected content.

    Lookup and loader callables are injected so tests can use simple fakes.
    Exceptions and timeouts become a generic dependency-failure result; their
    messages are never returned. A missing record or policy denial is an
    ordinary denial. No document content is returned on either failure.
    """

    if not _non_empty_text(document_id):
        return _result(Outcome.DENIED)

    outcome, _identity, user = _verified_user(
        supplied_identity, authenticate, load_user_metadata
    )
    if outcome is not Outcome.ALLOWED or user is None:
        return _result(outcome)

    try:
        document_record = load_document_metadata(document_id)
    except Exception:
        return _result(Outcome.DEPENDENCY_FAILURE)

    if document_record is None:
        return _result(Outcome.DENIED)

    document = _parse_document(document_record)
    if document is None or not is_authorized(user, document):
        return _result(Outcome.DENIED)

    try:
        content = load_protected_content(document_id)
    except Exception:
        return _result(Outcome.DEPENDENCY_FAILURE)

    return BoundaryResult(
        outcome=Outcome.ALLOWED,
        documents=(AuthorizedContent(document_id=document_id, content=content),),
    )


def authorize_search(
    supplied_identity: object,
    document_ids: Iterable[object],
    *,
    authenticate: Callable[[object], object],
    load_user_metadata: Callable[[str], object],
    load_document_metadata: Callable[[str], object],
    load_protected_content: Callable[[str], object],
) -> BoundaryResult:
    """Authorize all candidate metadata before loading any candidate content.

    Ordinary policy denials exclude only their candidate. A missing document
    is also an ordinary denial. Any required lookup failure or timeout fails
    the whole search. Content is loaded only after every candidate's required
    authorization lookup has completed, and partial content is never returned.
    """

    if type(document_ids) not in (list, tuple):
        return _result(Outcome.DENIED)
    if any(not _non_empty_text(document_id) for document_id in document_ids):
        return _result(Outcome.DENIED)

    outcome, _identity, user = _verified_user(
        supplied_identity, authenticate, load_user_metadata
    )
    if outcome is not Outcome.ALLOWED or user is None:
        return _result(outcome)

    authorized_ids: list[str] = []
    for document_id in document_ids:
        try:
            document_record = load_document_metadata(document_id)
        except Exception:
            # No content has been loaded yet, so the whole request can fail closed.
            return _result(Outcome.DEPENDENCY_FAILURE)

        if document_record is None:
            continue

        document = _parse_document(document_record)
        if document is not None and is_authorized(user, document):
            authorized_ids.append(document_id)

    if not authorized_ids:
        return _result(Outcome.DENIED)

    loaded: list[AuthorizedContent] = []
    for document_id in authorized_ids:
        try:
            content = load_protected_content(document_id)
        except Exception:
            # Do not return content already loaded for earlier candidates.
            return _result(Outcome.DEPENDENCY_FAILURE)
        loaded.append(AuthorizedContent(document_id=document_id, content=content))

    return BoundaryResult(outcome=Outcome.ALLOWED, documents=tuple(loaded))
