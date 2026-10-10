"""Pure version-one document authorization decision."""

from dataclasses import dataclass
from enum import Enum, IntEnum


class Clearance(IntEnum):
    """Ordered clearance levels. Higher values grant more clearance."""

    LOW = 1
    MEDIUM = 2
    HIGH = 3


class AccessType(Enum):
    """Document access types recognized by the version-one policy."""

    PUBLIC = "public"
    DEPARTMENT_RESTRICTED = "department_restricted"


class UserRole(Enum):
    """Roles used by the demo; administrator status grants no access bypass."""

    USER = "user"
    ADMINISTRATOR = "administrator"


@dataclass(frozen=True)
class User:
    """Canonical user data supplied by the caller after external lookups."""

    identity: str | None
    is_authenticated: bool
    is_active: bool
    clearance: Clearance | None
    role: UserRole
    department: str | None = None


@dataclass(frozen=True)
class Document:
    """Canonical document authorization metadata; document content is omitted."""

    sensitivity: Clearance | None
    access_type: AccessType
    department: str | None = None


def _is_non_empty_text(value: object) -> bool:
    """Return whether value is a plain string containing non-whitespace text."""

    return type(value) is str and bool(value.strip())


def is_authorized(user: object, document: object) -> bool:
    """Return True only when all version-one document-reading checks pass.

    The function accepts canonical User and Document records and performs no
    I/O. Authentication claims and records are supplied by the caller; this
    function does not verify tokens or prove that those claims are genuine.

    False is the only denial result. No denial details or protected content are
    returned. Callers must also fail closed if a required lookup fails or times
    out, and must reject conflicting source metadata before building records.
    """

    # Exact type checks keep malformed inputs and unexpected subclasses from
    # supplying surprising values or behavior.
    if type(user) is not User or type(document) is not Document:
        return False

    if type(user.is_authenticated) is not bool or not user.is_authenticated:
        return False
    if type(user.is_active) is not bool or not user.is_active:
        return False
    if not _is_non_empty_text(user.identity):
        return False

    if type(user.clearance) is not Clearance:
        return False
    if type(document.sensitivity) is not Clearance:
        return False
    if type(user.role) is not UserRole:
        return False
    if type(document.access_type) is not AccessType:
        return False

    # IntEnum values compare numerically according to the declared ordering.
    if user.clearance < document.sensitivity:
        return False

    if document.access_type is AccessType.PUBLIC:
        return True

    if document.access_type is AccessType.DEPARTMENT_RESTRICTED:
        if not _is_non_empty_text(user.department):
            return False
        if not _is_non_empty_text(document.department):
            return False
        # No case folding or other normalization: the match is exact.
        return user.department == document.department

    # This also denies any future or malformed access type not handled above.
    return False
