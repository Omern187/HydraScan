# Code logic and operational bug review

Read when the task includes functional bugs, code logic, incorrect behavior, broken features, or anything disrupting normal use. Strix findings are one input to security review; they do not replace this workflow or establish that the application works correctly.

## Establish what should work

Map the important features and user journeys from the supplied requirements, issue descriptions, API contracts, UI, and repository. Record the relevant actors, valid inputs, expected outputs, persisted state, external effects, and business invariants. Distinguish documented rules, observed behavior, and inferred intent. Existing code and tests can encode the same bug; compare them with the actual requirement and invariant.

For each critical journey, record a compact chain:

```text
Trigger -> preconditions -> code branches -> state/data changes -> external effects -> user-visible outcome
```

Include backend handlers, database operations, background jobs, and client rendering when the feature crosses them. A working button, HTTP 200, or green test suite does not prove the intended effect occurred.

If behavior is ambiguous and the answer would change the diagnosis or fix, ask a focused product question while reviewing independent paths. Keep an inferred rule labeled as an assumption until it is supported. Do not patch a deliberate business rule merely because another rule seems preferable.

## Inspect reachable logic

Review the implementation of important paths, their direct callers, shared helpers, and relevant configuration. Follow values through conversions and persistence; follow control through early returns, exceptions and asynchronous work. Prioritize code that governs correctness rather than only syntax errors or suspicious keywords.

Check applicable cases:

- Conditions and branches: reversed comparisons, wrong Boolean combinations, omitted cases, unreachable branches, fall-through, incorrect defaults, precedence, early returns and inconsistent validation across callers.
- Calculations: wrong formula/units, rounding order, currency precision, signs, zero/negative values, overflow, off-by-one limits, array indices, time zones and interval endpoints.
- Types and values: null/undefined/empty distinctions, truthiness of valid zero/false values, coercion, unchecked parsing, invalid enums, Unicode normalization and incompatible serialized shapes.
- State transitions: prerequisites, wrong ordering, partial state, stale/derived state, reset behavior, cancellation, navigation, reload and persistence across sessions.
- Async/concurrency: missing awaits, rejected promises, out-of-order responses, stale closures, double effects, lost updates, duplicate submissions, missing idempotency and non-atomic operations.
- Collections and queries: filters, joins, sort order, pagination/cursors, skipped/duplicate results, cache keys/invalidation and incorrect ownership or grouping assumptions.
- Integration boundaries: request/response shape, status interpretation, timeout/retry semantics, webhook handling, wrong environment endpoints, incompatible versions and third-party errors.
- Failures and recovery: swallowed exceptions, false success messages, endless spinners, missing cleanup, irreversible partial writes, failed rollback, retries after partial success and unrecoverable error states.
- Startup and lifecycle: missing/invalid configuration, migration incompatibility, resource initialization/disposal, file I/O errors, background-job scheduling, reconnect and upgrade behavior.

Keep an issue tied to a reachable execution path and a consequence. A code smell, lint warning or possible inefficiency becomes a bug only when it violates expected behavior or causes a demonstrated failure; otherwise report it as an observation with the missing evidence.

## Exercise how the product operates

When an authorized disposable/local or staging environment is available, use its normal entrypoints to run important journeys. Match runtime data/configuration to the reviewed revision. For each selected journey:

1. Run a legitimate example and verify the final UI/API outcome and actual persisted or external effect with synthetic fixtures.
2. Choose meaningful edge cases from the rules: empty data, one item, limits just below/at/above a boundary, valid zero/false, invalid input, duplicates, retries or a different supported role.
3. Exercise relevant failure paths using controlled dependency mocks, interrupted requests or test-only injected failures. Confirm understandable errors, correct cleanup and recoverability.
4. Where timing matters, use bounded concurrency or deterministic delays. Check the final invariant after the requests settle, not just individual successful responses.
5. Verify restart/reload/back navigation, alternate entrypoints, or another supported device/browser when they materially affect the feature.

Avoid triggering real payments, notifications, destructive operations or production migrations outside established scope. If a fixture requires unavailable services/accounts, report the specific untested path and continue others. A setup failure is not automatically a product bug; establish whether it arises from the application under supported configuration or from the test environment.

Use the project's existing unit, integration and end-to-end tools when they answer the question. Type/lint/build checks help identify defects but do not substitute for behavior checks. Do not add a new framework solely for a review when a small existing test or reproducible normal interaction will suffice.

For persistent data, import/export, lifecycle, background jobs and native applications, select probes from [behavioral-probes.md](behavioral-probes.md). Compare sibling implementations of the same feature against one invariant; checking the shared helper does not cover a caller that bypasses it. Choose from actual architecture and missing coverage rather than executing every probe on every app.

## Confirm and prioritize

For each candidate, record the expected rule, smallest reproducible trigger, actual outcome, reachable code path, effect and control case. Verify the alleged failure under supported inputs/configuration. Label deterministic source evidence separately from observed runtime reproduction and retain unresolved intent or environment questions as proof gaps.

Prioritize functional bugs by effect on users and data, how often the trigger occurs, affected scope, and available workaround:

- Blocking: application cannot start, core journey cannot complete, data loss/corruption, or consistently incorrect consequential results.
- Major: an important supported feature fails, state becomes inconsistent, or common inputs produce materially wrong results.
- Moderate: narrower scenarios fail with a practical workaround or recoverable effect.
- Minor: limited friction that does not materially block the journey.

Adjust to actual product context; these labels are not automatic CVSS scores or blanket severities. A bug can have both functional and security consequences: link the evidence and describe both rather than lose one aspect or double-count the same root cause.

## Fix and prove correct behavior

When fixes are requested, change the smallest responsible logic/state boundary using existing patterns. Check other callers affected by a shared helper. Validate against the requirement and meaningful sibling cases, not just the exact failing input.

A useful regression check asserts an observable result or invariant and fails on the defective version. Verify the original failed journey now succeeds, important legitimate cases remain correct, and errors/retries preserve data consistency. Run required repository checks appropriate to the changed component. State exactly what was executed and what remains source-only analysis.

Keep a bug-demonstration probe separate from a fix regression test. A script that passes because it asserts the old broken result confirms a reproduction; it does not validate remediation. After a fix, assert the intended invariant, and show failure on the defective version and success on the fixed version when feasible.

## Functional coverage record

Track each critical feature as well as the functional families in [coverage.md](coverage.md). Record:

```text
Feature/journey and expected invariant
Reviewed handlers/helpers and revision
Inputs, roles, configurations and transitions exercised
Outcome/state checked and supporting evidence
Findings, untested cases and next useful check
```

Inspecting a function does not establish its integration works, and exercising one journey does not clear all its branches. Resume unfinished paths from the checkpoint rather than repeating already validated cases.
