# Permission-Aware RAG Security Gateway

## Purpose

This beginner-friendly security portfolio project explores how a backend can
check document permissions before protected text is used in a retrieval-
augmented generation (RAG) workflow. It uses fictional demo data and is not a
production security gateway.

## Current status

**Phase 6: local authenticated API demo.** The project includes the pure
authorization policy, local authorization/retrieval/model/response boundaries,
a small FastAPI application, signed-token authentication, and `unittest` tests.
The project is not a production-ready RAG application.

Run the three-scenario local demo from the project root with:

```text
python demo.py
```

Install the listed dependencies, set a local signing secret, and run the API
from the project root in PowerShell:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
$env:RAG_GATEWAY_SECRET = "local-demo-secret-change-this-value-123456"
python -m uvicorn api:app --reload
```

Use the local demo accounts `engineer-demo` / `engineering-demo-password` or
`finance-demo` / `finance-demo-password` at `POST /auth/login`. Send the
returned bearer token to `POST /search` with `{"query":"demo search"}`.
These fictional credentials and the local secret are for this demo only; do
not reuse them or expose the app to an untrusted network.

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
- `response_boundary.py` creates a local preview only from a valid, non-empty
  authorized search result. It makes snippets from at most the first 80
  characters of each non-empty text document (adding `...` when truncated)
  and uses authorized document IDs as citations. Ordinary denials exclude
  only their candidate; dependency and malformed-result failures return no
  preview content.
- `model_boundary.py` builds model input from authorized results only and uses
  a local recording-model stub. `demo.py` runs authorized, denied, and
  dependency-failure scenarios with fictional in-memory dependencies, then
  prints only generic outcomes and whether the stub was invoked.
- `api.py` provides local login and protected-search endpoints. It verifies
  signed HS256 tokens and required expiry, issuer, audience, and subject claims
  using PyJWT. User clearance, department, active status, and role come from
  fixed server-side demo records; request bodies cannot set them.
- Standard-library `unittest` tests cover these policy and boundary behaviors.

“Implemented and tested” describes behavior represented by this code and its
tests. It does not establish production readiness or complete system security.

### Local demo authentication and simulated behavior

The API verifies signed tokens with PyJWT and creates `VerifiedIdentity` only
after signature and required-claim validation. Its demo accounts and all user,
document, and content records remain fictional and in memory. The separate
`demo.py` and unit-test boundaries also use injected identity fakes. The
candidate provider uses fixed in-memory mappings rather than ranking or
searching documents.

### Planned or not implemented

The project does not implement production identity management, production
user/document/content data adapters, a production API service, a vector
database, or an actual LLM. The local token verifier, API, and response preview
are demonstrations, not production authentication or a production
snippets/citations pipeline. Production audit logging and end-to-end safety
for deployed logs, debugging output, and real model context are also absent.

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
