# Cybersecurity validation and proof gaps

Read for security-focused reviews and consequential native candidates. The native runner prioritizes source locations; it neither proves exploitation nor replaces framework, role and deployment review. Read `security-review-tasks.json` as well as `candidates.json`. Assign these tasks to named reviewers and keep them open until there is evidence or an explicit gap.

## Resolve the actual input and boundary

For each signal, establish entrypoint -> input origin -> assignments/aliases/encoding -> exact control -> interpreter or protected operation -> observable consequence. Include sibling callers, imports, background consumers and generated copies. A local name, library reputation or unrelated safe sibling is not a control. Keep trusted literals/configuration distinct from external values. Validate control order; a check after the operation cannot protect it.

The Python helper follows simple local assignments, imports and evaluator aliases. It recognizes composed query text, some path constructions, TAR receivers and selected outbound clients. The JavaScript helper masks comments/literals, examines inline scripts, and prioritizes HTML sinks, dynamic interpreters and variable URL clients. These are bounded source heuristics: interprocedural flow, dynamic dispatch, template interpolation, regular-expression literals, framework middleware and database row-level policy require semantic review. A suppressed signal never clears a coverage family.

Review the declared JavaScript/framework gaps even when no candidate is emitted. Escaped embedded scripts and regex literals can cause spurious signals; nested templates and markup expressions can conceal operations. Python lexical binding, global/nonlocal state, computed imports and branch-dependent alias combinations remain incomplete. Attribute names such as `execute` do not establish a database receiver. Confirm imports and actual object types before accepting a query finding.

## Checks by boundary

| Boundary | Required proof and legitimate control |
| --- | --- |
| Database/query | Distinguish query structure from bound values. Trace dynamic identifiers and stored inputs too. Use a synthetic dataset to establish unexpected selection/change and compare the legitimate query and bound-value path. A composed query is a candidate until caller control and defenses are established. |
| Objects and tenants | Build a route × operation × role/tenant matrix for reads, writes, deletes, exports and jobs. Compare the same synthetic object under its owner, another user/tenant and applicable privileged roles. Check middleware, service policy and database enforcement; a lookup keyed only by ID is a review task, not proof that authorization is absent. |
| Files and archives | Establish the exact allowed root, canonical path, check order, links and overwrite permissions. Validate an allowed file/member and bounded rejected cases only in owned temporary fixtures. A path resolution call alone is not containment. Archive defaults depend on the actual runtime; inspect filter selection, member/link handling and filesystem effects. |
| Outbound requests | Trace URL origin, normalization, scheme/host/port, resolved addresses, credentials and redirect behavior before each request. Use an owned callback/mocked service within scope. An origin comparison can still leave address or redirect gaps; the native recognized-guard suppression is not proof of overall SSRF safety. |
| Browser rendering | Establish the actual browser context, input source, sanitization and supported rendering path. Compare user text with a trusted literal/text-only control. Source expressions inside response strings can become inline scripts; comments and ordinary strings alone do not execute. |
| Code/deserialization/processes | Resolve imported/local aliases and shadowed names, argument structure, serializer provenance and shell use. Demonstrate only an inert synthetic effect in owned fixtures. Legitimate data/arguments must still work. Do not execute unreviewed proof scripts just because a signal names an interpreter. |

## Decide and retain evidence

Use [reporting.md](reporting.md) to distinguish `candidate`, `source-confirmed` and `dynamic-confirmed`. Record supported roles, source/build, valid fixture setup, actual effect, legitimate control, counterevidence and any mock substitutions. Native ownership questions stay `review-task` until a reviewer supplies a finding record; do not include them in confirmed counts.

Use the [coverage matrix](coverage.md) and [multi-agent workflow](multi-agent-review.md) for untested boundaries. Missing credentials, unavailable runtime, interrupted agents and withheld source remain gaps. If an agent/tool rejects an action, preserve the actual failure and continue other permitted work without relaunching the same action under a disguised request.

When strengthening detectors, keep prior failing cases as regression data and also test distinct code forms and safe controls. Report candidate detection separately from runtime verification and agent discovery. Reusing the development cases measures regression performance, not generalization; do not label implementer-written variants as a blind independent audit.
