# Risk and bug coverage

Use this as a coverage map, not a payload catalog or a promise of exhaustive testing. Select concrete checks from the app's technology, assets, roles, and threat model. A class without an applicable sink can be not applicable only after inspection establishes why.

For a broad audit, track every row. Within each applicable row, enumerate important routes/call sites and roles; one successful check does not clear the entire family. Track these statuses: `not-started`, `partial`, `checked-no-issue-observed`, `finding`, `blocked`, `not-applicable`. Add the method, evidence, checked surfaces, missing surfaces, and reason. A finding does not imply full coverage of its family.

## Core application coverage

| Family | What to establish | Practical evidence or validation |
| --- | --- | --- |
| SQL and data query injection | SQL, NoSQL, ORM raw queries, query DSLs, filters, sort/identifier composition, LDAP and XPath where used; include stored inputs reused by later jobs | Trace input into query construction. Distinguish bound values from unsafe identifiers/operators. Validate on a synthetic dataset; include a legitimate query control. |
| Command, code, and template injection | Shell invocation, dynamic evaluation, server templates, script runners, plugin entrypoints, expression engines | Establish attacker control and actual interpreter context. Inspect argument boundaries and registered helpers. Demonstrate only an inert local marker inside a disposable instance. |
| XSS and content injection | Stored/reflected/DOM XSS; HTML, attribute, URL, JavaScript, CSS and Markdown rendering; unsafe rich text and SVG; DOM clobbering | Confirm the actual render context, sanitizer configuration, and browser execution using a synthetic account. Search sinks and alternate renderers, including exports and admin views. |
| Protocol and header handling | Response splitting, unsafe redirects, host-header trust, forwarded headers, parameter pollution, ambiguous parsing, request smuggling and cache poisoning | Compare application/proxy normalization and trusted-hop configuration. Confirm response effects. Smuggling/cache tests require an isolated environment, not shared production traffic. |
| Authorization and tenant isolation | Object, function and property access; IDOR/BOLA; role escalation; mass assignment; file/export and background-job ownership | Compare two controlled users/tenants and applicable privileged roles across read/write/delete/export, batch operations, API aliases, and alternate methods. UI hiding is not a server control. |
| Authentication and recovery | Login, reset/invite links, email change, MFA, passkeys, SSO/OAuth/OIDC/SAML, token verification, account linking | Trace identity binding, expiry, one-use enforcement, signature/issuer/audience checks, redirect handling, state/nonce/PKCE where applicable. Use test accounts; never credential-stuff real users. |
| Sessions and cross-origin actions | Session fixation, expiry/revocation/logout, cookie scope/flags, CSRF, CORS credentials/origins, WebSocket origin validation, clickjacking | Check the deployed behavior and configuration together. Reproduce a meaningful action with controlled origins/accounts. Missing headers alone do not prove a high-impact exploit. |
| SSRF and outbound trust | URL importers, previews, webhooks, redirects, DNS resolution/rebinding, IPv4/IPv6 handling, unsafe upstream API consumption | Trace every fetch and its pre-request/redirect checks. Use a controlled callback or mocked internal service; do not retrieve real metadata credentials or probe unrelated hosts. |
| Files, paths and archives | Traversal, arbitrary read/write, unsafe filename handling, symlink/hardlink escape, archive extraction, recursive copy, backup/restore, upload execution | Establish containment before the operation after applicable decoding/canonicalization. Validate using temporary fixtures. Check overwrite permissions inside the allowed root as well as escapes. |
| Parsers and serialization | Unsafe deserialization, XML external entities, insecure parser factories, type confusion, prototype pollution, malformed document imports | Enumerate parser/converter/codec variants and caller overrides. Check that failures do not silently disable controls. Use inert fixtures with bounded size/depth. |
| Data exposure and privacy | Excessive fields, secrets in code/build/logs/URLs/client storage, error traces, public backups, source maps, exports, caching of private data | Confirm who can obtain which sensitive information. Redact evidence. Distinguish a secret-shaped string from a usable credential; never test a credential against an unrelated service. |
| Cryptography and transport | Password hashing, randomness, encryption modes, TLS verification, at-rest protection, key lifecycle, token signing | Inspect actual APIs and deployment settings. Link weaknesses to protected assets and realistic attacker capability. At-rest claims need configuration/code access, not an external HTTP scan alone. |
| Business logic and integrity | Price/quantity/discount tampering, missing server invariants, workflow skipping, replay, webhooks, idempotency, double spend, TOCTOU/races | Write the invariant first. Use synthetic transactions and narrowly bounded concurrency in staging. Never charge cards, send real notifications, or change customer balances merely to prove a bug. |
| Resource abuse and exceptional paths | Missing pagination/size/depth/time limits, regex complexity, expensive GraphQL queries, decompression bombs, repeated retries, dependency failure, fail-open behavior | Prefer configuration/source reasoning and small bounded inputs. Use injected failures in local tests. Do not perform a live stress/DoS test without a separately established safe test scope. |
| Dependencies and supply chain | Direct/transitive versions, lockfiles, install/build scripts, dependency provenance, plugin/update signatures, artifact integrity, CI permissions | Verify exact versions against current primary advisories and affected configurations. Inspect trusted build boundaries. A runtime scan cannot establish the integrity of the build pipeline. |
| Deployment and infrastructure | Debug/admin interfaces, environment configuration, exposed storage, service credentials, container privileges/mounts, network policy, cloud IAM | Review supplied manifests and exact authorized deployments. Distinguish a code default from an observed production setting. Do not enumerate unrelated networks or assume cloud ownership. |
| Logging, detection and recovery | Security events, redaction, log injection, audit attribution, alert routing, retention, backup/restore correctness | Inspect logs/pipeline and use synthetic events where allowed. An external scanner cannot verify that alerts reached responders or backups can restore correctly. |
| API contract and inventory | REST/GraphQL/gRPC/WebSockets, deprecated/shadow versions, schema validation, authorization per resolver/message, bulk fields, webhook trust | Map documented and discovered operations to implementation. Check object/property/function authorization and response minimization. Review spec hosts before feeding them to a scanner. |

## Functional bug coverage

Use [functional-bugs.md](functional-bugs.md) for the workflow. Track critical features individually as well as these families; code correctness and actual product operation both need evidence.

| Family | What to establish | Practical evidence or validation |
| --- | --- | --- |
| Critical user journeys | Signup/login, create/edit/delete, search, upload/download, checkout or other app-specific workflows | Use requirements and supported roles; record expected versus actual results. Distinguish a blocked test environment from an application failure. |
| Code logic and business rules | Wrong conditions/formulas, omitted branches, early returns, off-by-one errors, invalid defaults, mismatched units, type coercion and null/truthiness mistakes | Trace a supported trigger through callers, branch decisions and observable outcome. Compare with documented requirements/invariants. Keep ambiguous intended behavior labeled as a question. |
| Boundaries and data correctness | Empty/null/malformed input, Unicode, dates/time zones/DST, rounding/currency, extreme values, duplicate records, schema migration | Use table-driven examples at real boundaries. Verify persisted state and API results, not just a displayed success message. |
| Workflow and state transitions | Missing prerequisites, skipped steps, stale/derived state, cancellation, navigation/reload, inconsistent frontend/backend state and incomplete operations | Map permitted transitions and check end-to-end effects. Confirm a success response corresponds to completed work and state survives reload where expected. |
| State and concurrency | Double submits, stale views, out-of-order requests, cancellation, offline/reconnect, retries, conflict handling, atomicity | Reproduce with a small deterministic test or controlled delay. Confirm no lost updates, partial writes, duplicate effects, or stale permission use. |
| Integrations and background work | API contract mismatches, wrong status handling, missing awaits, failed jobs/webhooks, retry semantics, environment mismatch and incompatible versions | Test the actual integration or a faithful controlled dependency. Verify asynchronous completion and durable results; separate application failure from unavailable test infrastructure. |
| Errors, recovery and lifecycle | Swallowed exceptions, false success, endless loading, incomplete rollback/cleanup, failed startup, missing configuration, migration/upgrade errors and leaked resources | Inject bounded failures in local/staging tests and verify correct errors, data consistency, cleanup, restart and recovery. Inspect failing code paths even when the happy path passes. |
| UI and accessibility defects | Broken navigation/forms, errors/loading/empty states, mobile layouts, keyboard/focus, labels, contrast where relevant | Exercise actual supported viewports and user flows. Report measurable defects, not personal visual preferences. |
| Reliability and performance defects | Crashes, memory/resource leaks, incorrect caching, pagination gaps, slow critical operations, timeouts | Record conditions and a bounded measurement. Separate functional failure from a security availability issue; avoid claiming production scale from a tiny local sample. |

## Technology-specific extensions

Apply these only when the technology is present; keep a row stating why an extension is applicable or excluded.

| Technology | Additional boundaries |
| --- | --- |
| AI/LLM features | Direct/indirect prompt injection, untrusted retrieval/tool output, tool authorization, excessive permissions, cross-user memory, data leakage, unsafe generated code/output, cost limits. Use synthetic secrets and mocked tools; successful model persuasion alone is not a security impact. |
| Native mobile clients | Local storage/keystore, deep links, exported components, WebView bridges, transport trust, privacy permissions, update integrity, backend authorization. Use current OWASP MASVS/MASTG where applicable. |
| Desktop/Electron/extensions | Renderer/main boundaries, IPC validation, sandbox/context isolation, custom protocols, local files, extension permissions, signed updates and plugin trust. |
| Native services or memory-unsafe code | Reachable input parsers, bounds/lifetime/type errors, unsafe FFI. Use sanitizers and fuzzing in isolated local builds with bounded resources. |
| Multi-tenant/enterprise integrations | Per-tenant credentials, role mapping, provisioning/deprovisioning, SCIM, SSO, shared jobs/caches, audit ownership, integration permissions and webhook replay. |

## Standards and freshness

Use standards to organize checks and name controls; do not use Top Ten membership as proof of complete testing or compliance. Record the edition and verified requirement IDs only when mapping a finding to a standard. Do not guess IDs.

Baselines checked on 2026-10-10:

- [OWASP ASVS upstream](https://github.com/OWASP/ASVS): 5.0.0; choose applicable requirements and review depth rather than claim blanket certification.
- [OWASP WSTG](https://owasp.org/projects/web-security-testing-guide): released 4.2; distinguish versioned test IDs from evolving development content.
- [OWASP Top 10](https://owasp.org/projects/top-ten): 2025, for web risk classification.
- [OWASP API Security](https://api-security.owasp.org/): 2023, for API risk classification.
- [OWASP MASVS](https://mas.owasp.org/MASVS/) and [MASTG](https://mas.owasp.org/MASTG/): consult current primary material when reviewing mobile applications.

Recheck official sources when an audit requires current editions, framework behavior, advisories, tool flags, or version-specific requirements. Preserve a user-required older edition and label it explicitly.
