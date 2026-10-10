# Permission-Aware RAG Security Gateway

## Purpose

This student portfolio project explores how a backend can enforce document permissions in a retrieval-augmented generation (RAG) system. Its security goal is to prevent users from receiving or sending unauthorized document content to a language model.

## Status

**Phase 0 — Design and threat-model work.** Application implementation and automated tests have not yet been completed. The rules below describe proposed behavior, not existing controls.

## Proposed authorization rules

- Requests require a valid authenticated identity, and the user must exist and be active.
- User clearance must be at least the document's sensitivity. Public documents do not bypass this clearance check.
- Department-restricted documents require an exact match between the user's department and the document's department.
- Administrator status does not bypass document-reading checks.
- Missing or invalid required authorization metadata causes denial.
- Authorization dependency failures or timeouts fail closed.
- Authorization must succeed before document content enters retrieval results or model context.

## Planned roadmap

1. Define and implement authorization logic.
2. Add permission-filtered retrieval.
3. Write security tests for allowed and denied access paths.
4. Define security-focused audit events.
5. Expand project and security documentation.
6. Consider an optional user interface after the core behavior is established.

## Threat model

See the [threat model](docs/threat-model.md) for the proposed policy, security assumptions, and initial test plan.
