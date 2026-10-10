"""Create a local response preview from authorized search results only."""

from dataclasses import dataclass
from typing import Callable

from authorization_boundary import (
    AuthorizedContent,
    BoundaryResult,
    Outcome,
)
from retrieval_boundary import InMemoryCandidateProvider, search_with_candidates


SNIPPET_LENGTH = 80


@dataclass(frozen=True)
class ResponseSnippet:
    """A short text excerpt associated with an authorized document ID."""

    document_id: str
    text: str


@dataclass(frozen=True)
class ResponsePreview:
    """Safe outcome with snippets and citations only for an allowed search."""

    outcome: Outcome
    snippets: tuple[ResponseSnippet, ...] = ()
    citations: tuple[str, ...] = ()


def _failure() -> ResponsePreview:
    """Return a generic failure without document or dependency details."""

    return ResponsePreview(outcome=Outcome.DEPENDENCY_FAILURE)


def _format_authorized_results(result: object) -> ResponsePreview:
    """Validate boundary output and format only authorized, non-empty text."""

    if type(result) is not BoundaryResult:
        return _failure()
    if type(result.outcome) is not Outcome or type(result.documents) is not tuple:
        return _failure()

    if result.outcome in (Outcome.DENIED, Outcome.DEPENDENCY_FAILURE):
        if result.documents:
            return _failure()
        return ResponsePreview(outcome=result.outcome)
    if result.outcome is not Outcome.ALLOWED or not result.documents:
        return _failure()

    snippets: list[ResponseSnippet] = []
    citations: list[str] = []
    for document in result.documents:
        if type(document) is not AuthorizedContent:
            return _failure()
        if type(document.document_id) is not str or not document.document_id.strip():
            return _failure()
        if type(document.content) is not str or not document.content.strip():
            # Empty or non-text content makes this entire preview malformed.
            return _failure()

        content = document.content.strip()
        if len(content) > SNIPPET_LENGTH:
            snippet = content[:SNIPPET_LENGTH].rstrip() + "..."
        else:
            snippet = content
        snippets.append(ResponseSnippet(document_id=document.document_id, text=snippet))
        citations.append(document.document_id)

    return ResponsePreview(
        outcome=Outcome.ALLOWED,
        snippets=tuple(snippets),
        citations=tuple(citations),
    )


def search_and_preview(
    query: object,
    supplied_identity: object,
    *,
    candidate_provider: InMemoryCandidateProvider,
    authenticate: Callable[[object], object],
    load_user_metadata: Callable[[str], object],
    load_document_metadata: Callable[[str], object],
    load_protected_content: Callable[[str], object],
) -> ResponsePreview:
    """Search and format a preview without accepting content from the caller.

    Candidate selection, authorization, and content loading remain in the
    existing retrieval boundary. Only a valid, non-empty ALLOWED result is
    formatted. Errors produce generic outcomes with no protected data.
    """

    try:
        result = search_with_candidates(
            query,
            supplied_identity,
            candidate_provider=candidate_provider,
            authenticate=authenticate,
            load_user_metadata=load_user_metadata,
            load_document_metadata=load_document_metadata,
            load_protected_content=load_protected_content,
        )
    except Exception:
        return _failure()

    return _format_authorized_results(result)
