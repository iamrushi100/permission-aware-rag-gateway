"""Authorized local retrieval with ID-only candidate selection and TF-IDF ranking.

The small term-to-ID catalog selects candidates without reading document
content. The existing authorization boundary validates metadata and loads
only authorized text; TF-IDF ranking runs afterward on that authorized text.
"""

import math
import re
from collections import Counter
from collections.abc import Mapping

from authorization_boundary import (
    BoundaryResult,
    Outcome,
    authorize_search,
)


class InMemoryCandidateProvider:
    """Return IDs for catalog labels whose terms are present in the query.

    The mapping is a tiny, manually prepared candidate index. Its values are
    IDs only; document content is not available to this provider.
    """

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
        self._candidate_ids_by_label = copied_candidates

    def select_candidate_ids(self, query: object) -> tuple[str, ...]:
        """Select IDs by matching catalog-label terms, never by document text."""

        if type(query) is not str:
            return ()
        query_terms = set(_terms(query))
        if not query_terms:
            return ()

        selected: list[str] = []
        seen: set[str] = set()
        for label, document_ids in self._candidate_ids_by_label.items():
            label_terms = set(_terms(label))
            if label_terms and label_terms.issubset(query_terms):
                for document_id in document_ids:
                    if document_id not in seen:
                        selected.append(document_id)
                        seen.add(document_id)
        return tuple(selected)


_WORD_PATTERN = re.compile(r"\w+", re.UNICODE)


def _terms(text: str) -> tuple[str, ...]:
    """Split text into lowercase word tokens for the local ranking demo."""

    return tuple(_WORD_PATTERN.findall(text.casefold()))


def _rank_authorized_documents(query: str, result: BoundaryResult) -> BoundaryResult:
    """Rank authorized text with TF-IDF; denied content is never in this corpus."""

    if result.outcome is not Outcome.ALLOWED:
        return result
    if any(
        type(document.content) is not str or not document.content.strip()
        for document in result.documents
    ):
        return BoundaryResult(outcome=Outcome.DEPENDENCY_FAILURE)

    query_terms = set(_terms(query))
    if not query_terms:
        return BoundaryResult(outcome=Outcome.DENIED)

    token_lists = [_terms(document.content) for document in result.documents]
    document_frequencies = Counter(
        term for tokens in token_lists for term in set(tokens)
    )
    document_count = len(token_lists)
    scores: list[float] = []

    for tokens in token_lists:
        term_counts = Counter(tokens)
        token_count = len(tokens)
        score = 0.0
        if token_count:
            for term in query_terms:
                frequency = term_counts[term]
                if frequency:
                    inverse_document_frequency = math.log(
                        (document_count + 1)
                        / (document_frequencies[term] + 1)
                    ) + 1.0
                    score += (frequency / token_count) * inverse_document_frequency
        scores.append(score)

    # The index is a tie-breaker, preserving the catalog order for equal scores.
    ranked_indexes = sorted(
        range(len(scores)), key=lambda index: (-scores[index], index)
    )
    ranked = tuple(result.documents[index] for index in ranked_indexes)
    return BoundaryResult(outcome=Outcome.ALLOWED, documents=ranked)


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

    if type(query) is not str or not query.strip() or not _terms(query):
        return BoundaryResult(outcome=Outcome.DENIED)

    result = authorize_search(
        supplied_identity,
        document_ids,
        authenticate=authenticate,
        load_user_metadata=load_user_metadata,
        load_document_metadata=load_document_metadata,
        load_protected_content=load_protected_content,
    )
    return _rank_authorized_documents(query, result)
