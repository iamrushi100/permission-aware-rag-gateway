# Permission-Aware RAG Security Gateway

## Purpose

This beginner-friendly security portfolio project explores how a backend can
check document permissions before protected text is used in a retrieval-
augmented generation (RAG) workflow. It uses fictional demo data and is not a
production security gateway.

## Current status

**Phase 4: local command-line demonstration.** A pure authorization policy, a
simulated authorization boundary, an in-memory ID-only candidate provider, a
recording-model stub, and `unittest` tests exist. The project is not a
production-ready RAG application.

Run the three-scenario local demo from the project root with:

```text
python demo.py
```

Run the test suite with:

```text
python -m unittest discover -s tests -v
```

This command is documented for running the suite; this README does not claim
that tests have passed in every environment.

### Implemented and tested in this project

- `authorization.py` defines the pure `is_authorized(user, document) -> bool`
  policy, including ordered clearance checks, public-document clearance checks,
  exact department matching for restricted documents, and no administrator
  bypass.
- `authorization_boundary.py` demonstrates a simulated identity-checking
  seam and injected metadata/content dependencies. It validates metadata before
  constructing canonical records and returns generic denial or dependency-
  failure outcomes.
- Multi-document authorization checks every candidate's metadata before
  loading any protected content. An ordinary policy denial excludes only that
  candidate (T14). A metadata lookup failure or timeout fails the whole search
  before any candidate content is loaded (T16). A content-loader failure
  returns no partial search result.
- `retrieval_boundary.py` provides deterministic exact-query-to-document-ID
  candidate selection in memory. It stores and returns IDs only; it is a demo
  candidate provider, not a search engine.
- `model_boundary.py` builds model input from authorized results only and uses
  a local recording-model stub. `demo.py` runs authorized, denied, and
  dependency-failure scenarios with fictional in-memory dependencies, then
  prints only generic outcomes and whether the stub was invoked.
- Standard-library `unittest` tests cover these policy and boundary behaviors.

“Implemented and tested” describes behavior represented by this code and its
tests. It does not establish production readiness or complete system security.

### Simulated behavior

The identity-checking component and data dependencies are injected test
seams. Tests use fakes, including a `VerifiedIdentity` marker; it does not
perform or represent genuine cryptographic or token verification. The
candidate provider uses fixed in-memory mappings rather than ranking or
searching documents.

### Planned or not implemented

The project does not currently implement real token verification, production
user/document/content data adapters, an API server, a vector database, an
actual LLM, or a complete snippets/citations/response pipeline. It also does
not implement production audit logging. Requirements concerning responses,
logs, debugging output, snippets, citations, and real model context remain
end-to-end requirements until those components exist and are tested.

## Approved version-one authorization policy

- A request requires a valid authenticated identity; the user must exist and
  be active.
- Required identity, clearance, sensitivity, access type, and access-specific
  metadata must be present and valid. Missing, malformed, conflicting, or
  unrecognized required metadata denies access.
- User clearance must be at least document sensitivity. Public documents do
  not bypass clearance or other baseline checks.
- Department-restricted documents require an exact, case-sensitive department
  match.
- Administrator status does not bypass document-reading checks.
- Required authorization dependency failures and timeouts fail closed.
- Authorization must succeed before protected content enters results,
  snippets, citations, or model context. T14 excludes an ordinarily denied
  candidate while retaining authorized candidates. Under T16, a metadata
  dependency failure or timeout fails the entire multi-document search.

## Roadmap

1. Extend the tested boundary toward a permission-filtered retrieval flow.
2. Add further security tests for data sources, responses, citations, and
   model-context construction.
3. Define safe audit events and verify that secrets and protected content are
   excluded.
4. Improve documentation as implementation grows.
5. Consider an optional UI after core behavior is established.

See the [threat model](docs/threat-model.md) for the policy, current control
coverage, test plan, assumptions, and open questions.
