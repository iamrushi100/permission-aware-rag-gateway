"""In-memory candidate selection connected to the authorization boundary.

This is a deterministic demo candidate source, not a search engine. It stores
only query-to-document-ID mappings. Protected content is handled only by the
existing authorization boundary after its checks succeed.
"""

from collections.abc import Mapping

from authorization_boundary import (
    BoundaryResult,
    Outcome,
    authorize_search,
)


class InMemoryCandidateProvider:
    """Return document IDs for an exact query, without storing document data."""

    def __init__(self, candidates_by_query: Mapping[str, tuple[str, ...]]):
        copied_candidates = {}
        for query, document_ids in candidates_by_query.items():
            if type(query) is not str:
                raise ValueError("Queries must be strings")
            if type(document_ids) not in (list, tuple):
                raise ValueError("Each query must map to a list or tuple of IDs")
            if any(
                type(document_id) is not str or not document_id.strip()
                for document_id in document_ids
            ):
                raise ValueError("Candidate IDs must be non-empty strings")
            copied_candidates[query] = tuple(document_ids)
        self._candidates_by_query = copied_candidates

    def select_candidate_ids(self, query: object) -> tuple[str, ...]:
        """Select IDs by exact query match; unknown or invalid queries match none."""

        if type(query) is not str:
            return ()
        return self._candidates_by_query.get(query, ())


def search_with_candidates(
    query: object,
    supplied_identity: object,
    *,
    candidate_provider: InMemoryCandidateProvider,
    authenticate,
    load_user_metadata,
    load_document_metadata,
    load_protected_content,
) -> BoundaryResult:
    """Select IDs, then pass them to the existing authorization boundary.

    Candidate-provider failures have the same generic fail-closed outcome as
    other dependency failures. No candidate IDs or exception details are
    included in the returned result.
    """

    try:
        document_ids = candidate_provider.select_candidate_ids(query)
    except Exception:
        return BoundaryResult(outcome=Outcome.DEPENDENCY_FAILURE)

    return authorize_search(
        supplied_identity,
        document_ids,
        authenticate=authenticate,
        load_user_metadata=load_user_metadata,
        load_document_metadata=load_document_metadata,
        load_protected_content=load_protected_content,
    )
