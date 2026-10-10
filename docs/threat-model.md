# Threat Model — Permission-Aware RAG Security Gateway

**Status:** Initial draft  
**Project stage:** Phase 0 — Design  
**Data classification:** Fictional demo data only

## 1. Purpose

The Permission-Aware RAG Security Gateway is a learning and portfolio project that demonstrates how a backend can enforce document permissions before retrieved document text is passed to a large language model (LLM).

The primary security requirement is that unauthorized document content must not enter the model input.

This threat model defines the initial assets, users, trust boundaries, attacker goals, security rules, assumptions, and out-of-scope features.

## 2. Assets to protect

| Asset | Why it matters |
|---|---|
| Document contents | May contain restricted or confidential information. |
| Document titles and snippets | Can reveal sensitive information even when full text is hidden. |
| User identity | Determines whose permissions the backend evaluates. |
| Authentication tokens | Must not be forged or accepted after expiry. |
| Permission metadata | Determines which documents a user may access. |
| Retrieved context | Contains the text that may be sent to the LLM. |
| Citations and API responses | Must not expose unauthorized documents. |
| Audit events | Should record security decisions without storing secrets. |

## 3. Users and potential attackers

### Legitimate users

- Interns who can access permitted public documents.
- Engineers who can access permitted engineering documents.
- HR users who can access permitted HR documents.
- Finance users who can access permitted finance documents.
- An administrator with the explicitly defined demo permissions.

### Potential attackers

- An authenticated user attempting to access another department's documents.
- A user changing document IDs or request fields to gain additional access.
- A user submitting a forged, malformed, or expired token.
- A user asking questions designed to reveal restricted information indirectly.
- A user attempting to manipulate the LLM through prompt injection.

These are threat scenarios for the demo, not claims that an attack has already been tested.

## 4. Trust boundaries

The initial design identifies these boundaries:

1. **Client to API:** Requests and client-supplied fields are untrusted.
2. **API to identity and permission data:** Authorization decisions must use verified identity and current user records.
3. **Retrieval to context construction:** Only authorized search results may be used to build model context.
4. **Context construction to LLM interface:** The application must not pass unauthorized document text to this interface.
5. **Application to audit logs:** Logged information must be limited to what is needed for security review.

## 5. Security requirements

The proposed backend design must:

1. Verify authentication tokens using a trusted library.
2. Derive identity from verified token claims, not from a user-controlled request-body field.
3. Check the current user record and reject inactive or unknown users.
4. Deny access by default when permission metadata is missing, invalid, or unrecognized.
5. Check document authorization before document content enters retrieval results, snippets, citations, or model context, and before returning a document or its contents.
6. Restrict retrieval results to documents the requesting user is authorized to read.
7. Construct model context only from authorized results.
8. Return citations only for authorized documents.
9. Prevent unauthorized document content from appearing in responses, logs, debugging output, or error messages.
10. Avoid logging passwords, bearer tokens, full document text, or complete model context.

## 6. Initial authorization policy

The following are proposed version-one design requirements. They are not claims that controls have been implemented or verified.

A request may read a document only when all baseline checks pass:

- The request has a valid authenticated identity derived from verified authentication data.
- The user exists and is active.
- User identity and clearance, document sensitivity, and all required access metadata are present and valid.
- User clearance is greater than or equal to document sensitivity.
- The document's access type is recognized and its access-specific metadata is valid.
- No required authorization dependency has failed or timed out.

Access type adds these requirements to the baseline checks:

- A public document does not require a department match. Public status does not bypass authentication, active-user, metadata, or clearance checks.
- A department-restricted document requires an exact match between the user's department and the document's department.
- Administrator status does not bypass any document-reading check.

Missing, malformed, conflicting, or unrecognized required authorization metadata results in denial. If a required authorization dependency fails or times out during a multi-document search, the entire search request fails closed, even if authorization succeeded for other candidates. No candidate's protected content may be returned, and unchecked or unauthorized content must not enter model context. Authorization must succeed before document content enters retrieval results, snippets, citations, or model context. Unauthorized document content must not appear in responses, logs, debugging output, or error messages.

## 7. Initial deterministic test plan

Tests use fictional data and clearance levels ordered `low < medium < high`. In each test, all inputs not explicitly varied are valid and satisfy the proposed policy. An allow result permits the document content to enter authorized results and model context; a deny result requires that unauthorized document content remain absent from retrieval results, snippets, citations, model context, responses, logs, debugging output, and error messages.

| Test | Setup and single condition under test | Expected decision | Expected content-exposure outcome |
|---|---|---|---|
| T01 | Active authenticated user with valid identity and `medium` clearance; public document with valid sensitivity `medium` and access metadata. | Allow. | The authorized document content may enter results and model context. |
| T02 | Same valid baseline as T01, except user clearance is `low` and document sensitivity is `medium`. | Deny. | Document content is absent from results and model context and is not disclosed elsewhere. |
| T03 | Active authenticated user in `engineering` with `medium` clearance; department-restricted document in `engineering` with sensitivity `medium`. | Allow. | The authorized document content may enter results and model context. |
| T04 | Same valid baseline as T03, except the document department is `finance` while the user department is `engineering`. | Deny. | Document content is absent from results and model context and is not disclosed elsewhere. |
| T05 | Administrator with valid identity and sufficient clearance; a valid document whose access-specific checks pass. | Allow. | The authorized document content may enter results and model context. Admin status is not needed for the allow. |
| T06 | Same valid baseline as T05, except administrator clearance is `low` and document sensitivity is `medium`. | Deny. | Document content is absent from results and model context and is not disclosed elsewhere. |
| T07 | Valid active user and valid public access metadata; document sensitivity is missing. | Deny. | Document content is absent from results and model context and is not disclosed elsewhere. |
| T08 | Valid active user and document sensitivity; document access type is an unrecognized value. | Deny. | Document content is absent from results and model context and is not disclosed elsewhere. |
| T09 | Valid authenticated identity and otherwise-valid user/document data; user account is inactive. | Deny. | Document content is absent from results and model context and is not disclosed elsewhere. |
| T10 | Run separate subcases with valid user/document data: one where a required authorization dependency fails, and one where it times out during the decision. | Deny (fail closed) in both subcases. | No unchecked document content enters results or model context or is disclosed elsewhere. |
| T11 | Active authenticated user with clearance `medium`; document with sensitivity `medium`; all other checks pass. | Allow because clearance equals sensitivity. | The authorized document content may enter results and model context. |
| T12 | Valid active user and sufficient clearance; department-restricted document has a missing department. Run a separate subcase with an invalid department value. | Deny in both subcases. | Document content is absent from results and model context and is not disclosed elsewhere. |
| T13 | Valid authenticated active user and valid document; user clearance is missing. Run a separate subcase with an invalid clearance value. | Deny in both subcases. | Document content is absent from results and model context and is not disclosed elsewhere. |
| T14 | Search has otherwise-authorized candidates plus one document that fails authorization for this user. | Allow authorized candidates; deny the unauthorized document. | Unauthorized content does not enter results, snippets, citations, or model context; authorized content may do so. |
| T15 | Otherwise-valid user/document setup. Run separate subcases with an invalid, expired, and malformed authentication token. | Deny in every subcase. | No document content enters results or model context or is disclosed elsewhere. |
| T16 | Multi-document search has multiple candidates. Authorization succeeds for some candidates, but a required authorization dependency fails for or times out while checking another candidate. | Deny the entire search request (fail closed). | No candidate's protected content is returned; unchecked or unauthorized content does not enter model context; the response, errors, and debugging output reveal no protected content. |

These cases define intended checks only. They do not show that the controls exist or that any test has passed.

## 8. Attacker goals

Potential attacker goals include:

- Reading a restricted document directly by ID.
- Retrieving restricted text through search.
- Inferring the existence or title of a restricted document.
- Manipulating request fields to impersonate a more privileged user.
- Causing unauthorized content to enter the model context.
- Using prompt injection to attempt to override instructions or reveal information.
- Discovering credentials or sensitive document text through logs and errors.

## 9. Assumptions

- The initial demo uses fictional users and documents.
- Development and testing take place locally.
- Authentication and password hashing will use established libraries rather than custom cryptography.
- The initial retrieval system will use a simple keyword or TF-IDF baseline.
- A recording LLM stub will be used to inspect the exact input supplied by the application.
- Automated tests will cover explicitly documented scenarios.

These assumptions must be revisited if the architecture or scope changes.

## 10. Out of scope

The initial version does not claim to provide:

- Production-grade identity management or single sign-on.
- Multi-tenant isolation guarantees.
- A general-purpose attribute-based policy engine.
- Complete protection against every prompt-injection attack.
- Proof of how every real LLM will behave.
- Production deployment or a production security certification.

## 11. How security will be evaluated

The project will use unit, integration, and security regression tests.

Tests will cover authorized access, denied access, token failures, identity tampering, document-ID manipulation, restricted retrieval results, unauthorized model context, citations, prompt injection, and audit-log safety.

The recording stub will help verify what the application sends to the model interface in the tested scenarios.

Passing the test suite will provide evidence for those scenarios only. It will not prove that the application is completely secure.

## 12. Open questions

The following decisions remain to be confirmed during implementation:

- The exact database schema.
- The authentication and token configuration.
- The retrieval algorithm and ranking behavior.
- The API response format.
- The audit event schema.
- The exact definition and measurement of a confirmed leak.
- Whether an optional real-LLM adapter is worthwhile after the core tests pass.
