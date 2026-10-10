"""Run a local demonstration of authorized, denied, and failed searches."""

from dataclasses import dataclass

from authorization_boundary import Outcome, VerifiedIdentity
from model_boundary import ModelBoundaryResult, RecordingModel, search_and_record
from retrieval_boundary import InMemoryCandidateProvider


DEMO_CREDENTIAL = "demo-credential"
DEMO_QUERY = "show the demo document"


class DemoDependencies:
    """Small fictional in-memory identity, metadata, and content dependencies."""

    def __init__(self):
        self.user_calls = 0
        self.document_calls: list[str] = []
        self.content_calls: list[str] = []
        self.document_errors: dict[str, Exception] = {}
        self.user_record = {
            "identity": "demo-user",
            "is_active": True,
            "clearance": "medium",
            "role": "user",
            "department": "engineering",
        }
        self.document_records = {
            "authorized-doc": {
                "sensitivity": "medium",
                "access_type": "public",
            },
            "denied-doc": {
                "sensitivity": "medium",
                "access_type": "department_restricted",
                "department": "finance",
            },
            "failure-doc": {
                "sensitivity": "medium",
                "access_type": "public",
            },
        }
        self.protected_contents = {
            "authorized-doc": "FICTIONAL AUTHORIZED DOCUMENT CONTENT",
            "denied-doc": "FICTIONAL DENIED DOCUMENT CONTENT",
            "failure-doc": "FICTIONAL FAILURE SCENARIO CONTENT",
        }

    def authenticate(self, credential: object) -> VerifiedIdentity | None:
        """Accept only the fake local demo credential."""

        if credential != DEMO_CREDENTIAL:
            return None
        return VerifiedIdentity(subject="demo-user", verified=True)

    def load_user_metadata(self, subject: str) -> dict[str, object] | None:
        self.user_calls += 1
        if subject != self.user_record["identity"]:
            return None
        return self.user_record

    def load_document_metadata(self, document_id: str) -> dict[str, object] | None:
        self.document_calls.append(document_id)
        error = self.document_errors.get(document_id)
        if error is not None:
            raise error
        return self.document_records.get(document_id)

    def load_protected_content(self, document_id: str) -> str:
        self.content_calls.append(document_id)
        return self.protected_contents[document_id]


@dataclass(frozen=True)
class DemoRun:
    """Scenario state exposed for tests; the CLI prints only safe summary data."""

    result: ModelBoundaryResult
    model: RecordingModel
    dependencies: DemoDependencies


def _run_scenario(document_ids: tuple[str, ...], *, fail_metadata_lookup: bool = False) -> DemoRun:
    """Build fresh local dependencies and run one scenario through the boundary."""

    dependencies = DemoDependencies()
    if fail_metadata_lookup:
        dependencies.document_errors["failure-doc"] = TimeoutError(
            "SIMULATED PRIVATE LOOKUP DETAIL"
        )

    provider = InMemoryCandidateProvider({DEMO_QUERY: document_ids})
    model = RecordingModel()
    result = search_and_record(
        DEMO_QUERY,
        DEMO_CREDENTIAL,
        candidate_provider=provider,
        authenticate=dependencies.authenticate,
        load_user_metadata=dependencies.load_user_metadata,
        load_document_metadata=dependencies.load_document_metadata,
        load_protected_content=dependencies.load_protected_content,
        model=model,
    )
    return DemoRun(result=result, model=model, dependencies=dependencies)


def run_authorized_scenario() -> DemoRun:
    """Run a valid public-document request with sufficient clearance."""

    return _run_scenario(("authorized-doc",))


def run_denied_scenario() -> DemoRun:
    """Run a department mismatch; its protected content must not be loaded."""

    return _run_scenario(("denied-doc",))


def run_dependency_failure_scenario() -> DemoRun:
    """Run a required metadata timeout before any candidate content is loaded."""

    return _run_scenario(("authorized-doc", "failure-doc"), fail_metadata_lookup=True)


def main() -> int:
    """Print generic scenario outcomes without content or internal details."""

    scenarios = (
        ("Authorized request", run_authorized_scenario()),
        ("Denied request", run_denied_scenario()),
        ("Dependency failure", run_dependency_failure_scenario()),
    )

    print("Permission-Aware RAG Security Gateway - local demo")
    for name, run in scenarios:
        invoked = "yes" if run.model.inputs else "no"
        print(f"{name}: {run.result.outcome.name}; model invoked: {invoked}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
