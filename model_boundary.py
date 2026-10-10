"""Build a local model-input boundary from authorized search results only."""

import json
from dataclasses import dataclass
from typing import Callable

from authorization_boundary import (
    AuthorizedContent,
    BoundaryResult,
    Outcome,
)
from retrieval_boundary import InMemoryCandidateProvider, search_with_candidates


@dataclass(frozen=True)
class ModelBoundaryResult:
    """Safe outcome of a search-and-record operation; never includes documents."""

    outcome: Outcome
    response: str | None = None


class RecordingModel:
    """Local test stub that records exact inputs and returns a fixed response."""

    def __init__(self, response: str = "Recorded model response."):
        self.response = response
        self.inputs: list[str] = []

    def generate(self, model_input: str) -> str:
        """Record one text input and return the configured deterministic response."""

        self.inputs.append(model_input)
        return self.response


def _validated_search_result(
    result: object,
) -> tuple[Outcome, tuple[AuthorizedContent, ...] | None]:
    """Validate result shape while preserving genuine denial outcomes."""

    if type(result) is not BoundaryResult:
        return Outcome.DEPENDENCY_FAILURE, None
    if type(result.outcome) is not Outcome or type(result.documents) is not tuple:
        return Outcome.DEPENDENCY_FAILURE, None

    if result.outcome in (Outcome.DENIED, Outcome.DEPENDENCY_FAILURE):
        if result.documents:
            return Outcome.DEPENDENCY_FAILURE, None
        return result.outcome, None
    if result.outcome is not Outcome.ALLOWED or not result.documents:
        return Outcome.DEPENDENCY_FAILURE, None

    for document in result.documents:
        if type(document) is not AuthorizedContent:
            return Outcome.DEPENDENCY_FAILURE, None
        if type(document.document_id) is not str or not document.document_id.strip():
            return Outcome.DEPENDENCY_FAILURE, None
        # Existing demo content is text. Reject other objects instead of
        # implicitly stringifying potentially sensitive or unexpected values.
        if type(document.content) is not str or not document.content.strip():
            return Outcome.DEPENDENCY_FAILURE, None

    return Outcome.ALLOWED, result.documents


def _make_model_input(documents: tuple[AuthorizedContent, ...]) -> str:
    """Serialize only authorized IDs and content in a stable JSON format."""

    payload = {
        "documents": [
            {"document_id": document.document_id, "content": document.content}
            for document in documents
        ]
    }
    return json.dumps(
        payload,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    )


def search_and_record(
    query: object,
    supplied_identity: object,
    *,
    candidate_provider: InMemoryCandidateProvider,
    authenticate: Callable[[object], object],
    load_user_metadata: Callable[[str], object],
    load_document_metadata: Callable[[str], object],
    load_protected_content: Callable[[str], object],
    model: RecordingModel,
) -> ModelBoundaryResult:
    """Search, authorize, and invoke the local model stub only for valid results.

    The function accepts no document content argument and performs no content
    lookup itself. It builds model input only from non-empty, valid documents
    returned by ``search_with_candidates`` with an explicit ALLOWED outcome.
    All failures return a generic outcome without document content or exception
    details.
    """

    try:
        search_result = search_with_candidates(
            query,
            supplied_identity,
            candidate_provider=candidate_provider,
            authenticate=authenticate,
            load_user_metadata=load_user_metadata,
            load_document_metadata=load_document_metadata,
            load_protected_content=load_protected_content,
        )
    except Exception:
        return ModelBoundaryResult(outcome=Outcome.DEPENDENCY_FAILURE)

    outcome, documents = _validated_search_result(search_result)
    if outcome is not Outcome.ALLOWED or documents is None:
        return ModelBoundaryResult(outcome=outcome)

    try:
        response = model.generate(_make_model_input(documents))
    except Exception:
        return ModelBoundaryResult(outcome=Outcome.DEPENDENCY_FAILURE)

    if type(response) is not str:
        return ModelBoundaryResult(outcome=Outcome.DEPENDENCY_FAILURE)
    return ModelBoundaryResult(outcome=Outcome.ALLOWED, response=response)
