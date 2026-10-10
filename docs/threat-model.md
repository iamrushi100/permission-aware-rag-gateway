# Threat Model — Permission-Aware RAG Security Gateway

**Status:** Working design and implementation record
**Project stage:** Phase 5 — local authorized response-preview demo
**Data classification:** Fictional demo data only

## 1. Purpose and scope

This beginner-friendly portfolio project demonstrates authorization checks
that should happen before protected document text is used in a retrieval-
augmented generation (RAG) workflow. The primary security goal is to prevent
unauthorized document content from reaching a user or a model context.

The current project is a small local demonstration. The code and tests provide
evidence for specific policy and boundary behaviors, not proof that a complete
gateway is secure or production-ready.

## 2. Assets to protect

| Asset | Why it matters |
|---|---|
| Document contents | May contain restricted or confidential information. |
| Document titles and snippets | Can reveal sensitive information even when full text is hidden. |
| User identity | Determines whose permissions the backend evaluates. |
| Authentication tokens | Must not be forged or accepted after expiry. |
| Permission metadata | Determines which documents a user may access. |
| Retrieved context | Contains text that could be sent to an LLM. |
| Citations and responses | Must not expose unauthorized documents. |
| Audit events and debug output | Must not reveal secrets or protected content. |

## 3. Users and potential attackers

Legitimate demo users may include interns, engineers, HR users, finance users,
and administrators. Potential attacker actions include attempting another
department's documents, changing document IDs or request fields, presenting a
forged or expired token, seeking indirect disclosure, or trying prompt
injection. These are threat scenarios, not claims that the attacks have been
tested.

## 4. Current architecture and control status

### Implemented and covered by unit tests

- `authorization.py` contains the pure `is_authorized(user, document) -> bool`
  decision function. It accepts canonical records, performs no I/O, checks
  the caller-supplied authentication state, active status, identity, recognized
  enum values, clearance ordering, and exact case-sensitive department
  matching. The authentication flag is input to the policy, not evidence that
  identity or a token was genuinely verified. The policy gives administrators
  no reading bypass.
- `authorization_boundary.py` separates the pure policy from injected
  authentication, metadata lookup, and protected-content loading functions.
  Its `VerifiedIdentity` is a simulated test marker only; the injected
  authenticator does not perform cryptographic or real token verification and
  does not prove the caller's claims are genuine.
- The boundary validates the shape and values of required source metadata
  before building canonical `User` and `Document` records. Missing records or
  invalid/conflicting metadata are ordinary denials. Lookup exceptions and
  timeouts become generic dependency failures without returning exception
  messages or content.
- For multi-document search, the boundary completes all candidate metadata
  lookups and policy decisions before calling any protected-content loader.
  Ordinary policy denial excludes only that candidate (T14). A required
  metadata lookup failure or timeout fails the whole request before content
  loading (T16). If content loading fails after earlier authorized content
  was loaded, the returned result contains no partial content.
- `retrieval_boundary.py` supplies an in-memory exact-query-to-document-ID
  mapping. It returns IDs only and delegates to `authorize_search()`. This is
  a deterministic demo candidate provider, not a search engine.
- `response_boundary.py` calls the authorized retrieval flow and formats a
  local preview only from a valid, non-empty `ALLOWED` result. Each non-empty
  string document contributes a snippet of at most 80 characters; longer
  snippets end with `...`. Citations contain only the IDs of those authorized
  documents. Malformed results, empty content, and dependency failures produce
  no preview content. This is a demo formatter, not a production citation
  pipeline.
- Corresponding `unittest` files test these behaviors using fictional data and
  fake dependencies. Run the suite from the project root with:

  ```text
  python -m unittest discover -s tests -v
  ```

The command above is the documented invocation; this document makes no claim
that the suite passed in a particular run.

### Simulated behavior

Authentication and data access are supplied through injected test functions
and fakes. The simulated authenticator can return a `VerifiedIdentity` marker,
but no actual token signature, expiry, issuer, or audience is checked. The
in-memory candidate provider only maps exact query strings to configured IDs;
it does not search document content, rank results, or conceal whether an ID is
configured.

### Planned or not implemented

The project does not implement:

- Real token verification or production identity management.
- Production user, document-metadata, or protected-content data adapters.
- An API server or a production database.
- A vector database or a real retrieval/ranking algorithm.
- An actual LLM, production response path, or production snippets/citations
  pipeline. The local response preview is only a demonstration formatter.
- Production audit logging or a complete end-to-end logging/debug-output
  safety guarantee.

Consequently, requirements about preventing disclosure through production API
responses, logs, debugging output, production snippets/citations, or a real
LLM context remain design requirements whose end-to-end enforcement is not
implemented or verified. Local prototype boundaries cover snippets, citations,
and model-input construction using authorized results. Future integrations
must preserve that ordering and must not create side channels around it.

## 5. Trust boundaries

1. **Client to future API:** Client fields are untrusted. No API currently
   exists.
2. **Identity and permission data to policy:** Future adapters must provide
   trusted identity and current, validated records. Current authentication and
   lookup functions are simulated/injected.
3. **Candidate selection to authorization:** Candidate selection supplies IDs
   only. An ID is not evidence that its document may be read.
4. **Authorization to protected-content loading:** The existing boundary
   authorizes candidate metadata before loading content.
5. **Authorized results to local model input and response preview:** Both
   prototype boundaries use only authorized results and have tests. A real
   LLM integration and production response/citation path do not exist; future
   components must preserve the same authorized-only data flow.
6. **Application to future audit/debug output:** Logging is not implemented;
   future output must not contain credentials or unauthorized content.

## 6. Approved version-one authorization policy

These are the approved policy requirements. Their current implementation
coverage is described in Section 4; a listed requirement is not automatically
an end-to-end control.

A request may read a document only when all baseline checks pass:

- It has a valid authenticated identity derived from verified authentication
  data.
- The user exists and is active.
- User identity and clearance, document sensitivity, and all required access
  metadata are present and valid.
- User clearance is greater than or equal to document sensitivity.
- The document access type is recognized and its access-specific metadata is
  valid.
- No required authorization dependency has failed or timed out.

Access-specific rules:

- A public document does not require a department match. Public status does not
  bypass authentication, active-user, metadata, or clearance checks.
- A department-restricted document requires an exact match between the user's
  department and the document's department.
- Administrator status does not bypass any document-reading check.

Missing, malformed, conflicting, or unrecognized required authorization
metadata causes denial. A required authorization dependency failure or timeout
during a multi-document search fails the entire request, even if other
candidates passed policy checks. Under T16, no candidate content is returned,
and unchecked or unauthorized content must not reach model context. Under T14,
ordinary policy denial excludes only the denied candidate, allowing other
authorized candidates to proceed. In all flows, authorization must succeed
before protected content enters results, snippets, citations, or model context.
Unauthorized content must not appear in responses, logs, debugging output, or
errors.

## 7. Test plan and current test coverage

Tests use fictional data and clearance levels `low < medium < high`. The
existing unit tests cover the pure policy and simulated boundary, including
T14-like ordinary filtering and T16 metadata-failure handling. The full table
states the intended policy cases; it is not a claim that every row has a
one-to-one test or that tests have passed.

| Test | Setup and condition | Expected decision and content exposure |
|---|---|---|
| T01 | Active authenticated user with valid identity and `medium` clearance; public document with `medium` sensitivity. | Allow; authorized content may enter authorized results. |
| T02 | T01, except user clearance is `low`. | Deny; document content is excluded. |
| T03 | Active engineering user with `medium` clearance; engineering-restricted document with `medium` sensitivity. | Allow; authorized content may enter authorized results. |
| T04 | T03, except document department is `finance`. | Deny that candidate; its content is excluded. |
| T05 | Administrator passes all ordinary checks. | Allow; administrator status is not needed for the decision. |
| T06 | Administrator has `low` clearance for a `medium`-sensitivity document. | Deny; admin status does not bypass clearance. |
| T07 | Document sensitivity is missing. | Deny; content is excluded. |
| T08 | Document access type is unrecognized. | Deny; content is excluded. |
| T09 | User is inactive. | Deny; content is excluded. |
| T10 | Required authorization dependency raises an exception or times out. | Fail closed; no protected content is returned. |
| T11 | User clearance is `medium`; document sensitivity is `medium`; all other checks pass. | Allow because clearance equals sensitivity. |
| T12 | Department-restricted document has a missing or invalid department. | Deny; content is excluded. |
| T13 | User clearance is missing or invalid. | Deny; content is excluded. |
| T14 | Search contains authorized candidates and an ordinarily unauthorized candidate. | Return authorized candidates only; denied content is excluded from results, snippets, citations, and model context. |
| T15 | **Planned, unimplemented test scenario:** use an invalid, expired, or malformed authentication token. The current simulated authentication seam does not validate real token signatures, expiry, issuer, or audience. | Deny; no document content is exposed. |
| T16 | Multi-document search has candidates whose metadata checks pass and a candidate whose required metadata lookup fails or times out. | Fail the entire search before any content loading; return no candidate content and reveal no protected content in errors or debugging output. |

The boundary tests also check that unverified or missing identity causes zero
user-metadata, document-metadata, and content-loader calls, and that a content
loader failure returns no partial result. Integration tests check that the
candidate provider selects IDs only. The local response and model-input
boundaries have tests for deriving snippets, citations, and model input from
authorized results; they are prototype components, not production integrations.

## 8. Attacker goals

- Read a restricted document directly by ID or through search.
- Infer a restricted document's existence, title, or content.
- Manipulate request fields to impersonate a more privileged user.
- Cause unauthorized content to enter model context.
- Use prompt injection to try to override application instructions.
- Discover credentials or protected text through logs and errors.

These goals describe risks to evaluate; they are not claims of complete
mitigation.

## 9. Assumptions

- The demo uses fictional users and documents and is run locally.
- Future authentication and password handling will use established libraries,
  not custom cryptography.
- Future retrieval may begin with a simple keyword or TF-IDF baseline.
- A local recording-model stub exists to inspect supplied model input; it is
  not an LLM and does not generate model responses.
- Tests will be added as the corresponding components are implemented.

Revisit these assumptions when the architecture changes.

## 10. Out of scope and remaining risks

The project does not claim production identity management, multi-tenant
isolation, a general-purpose attribute-based policy engine, complete protection
against prompt injection, predictable behavior from every real LLM,
production deployment, or security certification. Current tests establish
only the behaviors they assert against the simulated components. In
particular, there is no real token verification, persistent data source,
production retrieval algorithm, API response path, real LLM/context
integration, or audit logger. Local model-input construction and response
preview are demos only.

## 11. Open questions

- What database schema and production data adapters, if any, should be used?
- Which authentication/token configuration should a future real adapter use?
- What retrieval algorithm and ranking behavior should replace the deterministic
  candidate mapping?
- What API response and citation formats should be exposed?
- What audit-event schema is useful without recording secrets or content?
- How should a leak be defined and measured in end-to-end tests?
- Is an optional real-LLM adapter worthwhile after the recording-stub tests?
