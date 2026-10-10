# Findings, coverage and continuation records

Scale the report to the request. A focused bug review can stay inline; a broad/repeated review benefits from saved Markdown plus a checkpoint. Respect workspace output conventions. Keep raw logs and runnable fixtures in intermediate directories; deliver redacted reports and intentional artifacts only.

## Report structure

1. Outcome: most consequential findings, confirmed versus unverified, and practical effect.
2. Scope: repositories, source revision/working-tree fingerprint, deployed build/hosts/ports, environment, roles/tenants, included/excluded assets, permissions relied on, dates and standard editions.
3. Findings: distinguish security vulnerabilities, functional bugs and hardening observations; lead with the requested emphasis and greatest demonstrated impact. In a functional review, lead with blocked journeys, wrong results and data-loss bugs. Deduplicate by root cause without dropping distinct locations or impacts.
4. Coverage: each requested family/extension with status, actual method and evidence, covered surfaces/roles, remaining gaps and reasons. A live-only review must disclose unavailable source/infra/logging coverage. Native runner rows are preliminary; candidate signals or completed processes do not justify clearing a family.
5. Fixes and validation when performed: exact patch state, tests and results, preserved behavior, retest evidence and unresolved decisions.
6. Continuation: specific next checks, required inputs and the saved checkpoint/run identifiers.

## Per-finding record

Use stable IDs across follow-up reviews. Include:

- ID, title and kind: security / functional / hardening.
- Severity: critical / high / medium / low / informational, with a short impact rationale for security findings. For functional bugs, use blocking / major / moderate / minor priority from [functional-bugs.md](functional-bugs.md) and explain the affected journey, data and workaround; do not imply CVSS applies to ordinary bugs.
- Proof state: `dynamic-confirmed` (observed reproduction), `source-confirmed` (complete reachable source trace), `candidate` (plausible with named proof gaps), or `hardening` (control improvement without established exploit).
- Confidence and prerequisites: known attacker position, access/role, user interaction, environment, and explicitly unverified assumptions.
- Affected source locations or method/endpoint and build: mark entrypoint, control and sink as applicable; use verified line numbers.
- Expected behavior/invariant, its source (requirement, contract or explicitly labeled inference), and observed behavior. For functional bugs include trigger, actual versus expected output/state, affected journey, frequency/reproducibility and workaround if available.
- Reproduction or trace, synthetic inputs, expected/actual results and evidence paths; label steps that were analyzed rather than executed. Redact credentials, tokens and customer data.
- Test surface and substitutions: actual app, component harness, source trace or packaged runtime; state which dependencies were mocked and which consequence was actually observed. Fixture setup failure or an unreachable trigger is not a confirmed finding.
- Counterevidence: controls actually checked, control-case result and remaining ambiguity.
- Demonstrated impact, with hypothetical extensions clearly labeled. Cite current primary advisories for dependency claims and distinguish version presence from reachable applicability.
- Recommended root-cause fix and state: proposed / applied-unverified / verified / needs-product-decision.
- Validation commands/results and meaningful remaining coverage gaps.

Only attach standard/CWE mappings after verifying them. Add CVSS only when the requested report benefits from it and a documented vector can be justified; label the version and reproduce the score with a trusted calculator/library. A qualitative severity does not require invented numerical precision.

For dependency scans, name the counting unit (affected package entries, advisories or established application vulnerabilities) and scan scope. Separate build/install exposure from shipped runtime exposure using the actual packaging; a devDependency can still be the application's runtime. Before promoting an advisory to a confirmed finding, establish the affected version, configuration and reachable feature or attacker prerequisite. Do not report an aggregate scanner severity as the severity of the application without that evidence.

## Coverage row example

```text
Family: authorization and tenant isolation
Status: partial
Checked: GET /records/:id, test users A and B in separate tenants
Evidence: controlled cross-tenant request denied; route and policy trace recorded
Remaining: write/delete/export endpoints; no privileged account available
Next action: review export handler in source; request a test admin only for admin-flow validation
```

An untested write/export path stays open even if the read path is safe. If a check finds a bug, set the family to `finding` and separately record which subchecks remain untested.

## Checkpoint for continuing

Record native `security-review-tasks.json` entries as open questions with a named owner and outcome. They are not confirmed vulnerabilities.

For ongoing reviews, save `review-state.md` alongside the consolidated report. Record:

- Assessment ID, last update time/time zone, skill/runner revision, report location.
- Exact target/source/deployed build, requested mode, scope/exclusions and established authorization. Never store secret values or assume approval transfers to new hosts.
- Account role/tenant labels and how access is supplied; use references to approved secret stores, not credentials.
- Completed checks and evidence, family and per-feature/journey statuses, open candidate IDs and proof gaps, blockers and next actions in impact order.
- For a delegated review, agent/lane ownership, statuses, evidence directories, independent validation outcomes, duplicate mappings and remaining coverage. Track each agent's live processes/runs and cleanup owner.
- Changes applied, fix states, tests already run, unresolved product decisions.
- Native runner/Python version, source fingerprint and inventory exclusions, working/run directories, explicit check definitions and outcomes, log references, and process/session identities if runtime work remains active. Record agent and resource limits separately; the CLI does not save or restore agent sessions.
- Stop reason, any unexpected effects and cleanup state. Redact commands/logs containing secrets.

When reporting a blocked or interrupted check, state the concrete evidence and affected action: unavailable dependency, observed tool rejection or runtime failure. Distinguish that from unfinished reporting or an untested surface. Ambient browser content and a help page alone are not evidence that a tool or policy blocked the review; continue independent authorized work when possible.

On continuation, read the checkpoint and relevant findings, verify reality against recorded state, and proceed with the next useful check. Re-read only changed or relevant source rather than repeat a finished whole-app audit. Preserve previous evidence, record superseded findings explicitly, and do not infer approval for a new deployment, cloud upload, increased cost, external message or production effect. For native runs, place reviewer findings and decisions in the designated manual-note sections; `collect` refreshes generated summaries without re-running checks or validating candidates. See [engine.md](engine.md).

## Quality gate

Before delivering, check that every confirmed finding has evidence, every severity has a justified consequence, every claimed test actually ran, and all interrupted/blocked coverage is visible. Verify report links and line numbers against the reviewed revision. Distinguish skill-format validation, runner tests, static candidates and application behavior testing; passing tooling checks does not establish application security or correctness. Inspect excluded files and runtime/artifact gaps, and redact source snippets and raw logs before publication.

For state-changing findings, record the durable and post-reload outcome when relevant; UI text alone is insufficient. Distinguish a successful bug-demonstration script from a successful fix regression test. Record invalidated candidates and failed exploratory fixtures in the checkpoint without adding them to the finding count. Existing green tests do not clear branches they did not exercise.

Deduplicate consequences of the same root cause: for example, chunk-wise text decoding can corrupt a field, merge distinct keys and incorrectly reject a byte-limit boundary. Record those as impact variants unless distinct broken controls justify separate findings. A positive control disproves only the claim it exercises; a supposedly clean fixture can still contain an independently demonstrated defect.
