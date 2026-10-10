# Strix engine integration and provenance

## Basis for this skill

Inspected upstream: [usestrix/strix](https://github.com/usestrix/strix), commit `62b496430da5df5e9e79a190e7af6f92529883a3`, checked 2026-10-10; `pyproject.toml` declares version `1.7.0`. Upstream is Apache-2.0 licensed. These instructions are an original adaptation, with upstream linked for attribution; no upstream executable or full skill pack is bundled.

Useful upstream sources at that revision:

- [Application review skill](https://github.com/usestrix/strix/blob/62b496430da5df5e9e79a190e7af6f92529883a3/skills/application-security-testing/SKILL.md): choose the assessment per asset.
- [CLI pentest skill](https://github.com/usestrix/strix/blob/62b496430da5df5e9e79a190e7af6f92529883a3/skills/penetration-testing-with-strix/SKILL.md): execution, artifacts and coverage limits.
- [Remediation skill](https://github.com/usestrix/strix/blob/62b496430da5df5e9e79a190e7af6f92529883a3/skills/fix-security-vulnerabilities-with-strix/SKILL.md): fixes and retesting.
- [Source-aware discovery](https://github.com/usestrix/strix/blob/62b496430da5df5e9e79a190e7af6f92529883a3/strix/skills/analysis/source_aware_discovery.md), [counterevidence](https://github.com/usestrix/strix/blob/62b496430da5df5e9e79a190e7af6f92529883a3/strix/skills/analysis/counterevidence.md), and [fix verification](https://github.com/usestrix/strix/blob/62b496430da5df5e9e79a190e7af6f92529883a3/strix/skills/analysis/fix_verification.md): keep call sites distinct, establish controls, and verify real closure.
- [CLI reference](https://docs.strix.ai/usage/cli) and [coding-agent integration](https://docs.strix.ai/integrations/coding-agents): current installation and supported flags.

Upstream has consumer skills in `skills/` and engine knowledge packs in `strix/skills/`; they serve different purposes. This skill can work without installing either pack. Do not load all upstream skills or copy their policies into the conversation by default.

Strix is the security-testing engine. Assess general code logic, broken workflows and operational defects using [functional-bugs.md](functional-bugs.md), source analysis and the application's own test/runtime tools. A clean Strix run does not establish that features, calculations or integrations work correctly.

## Before execution

1. Confirm scope and active-test authorization from the user/conversation. Inspect the target, roles, exclusions, permitted effects, and available budget. Prepare everything locally before asking about a genuinely missing authorization.
2. Check `strix --version`, `strix --help`, and Docker availability (`docker info` with bounded wait). Use the installed version's semantics; fail clearly on unsupported flags. Report prerequisites without making missing Docker a reason to upload private source to a cloud service.
3. If installation is within the user's request, use upstream's documented installation method for the actual platform. Prefer an isolated tool environment (upstream documents `pipx install strix-agent`) or an inspected, pinned release. On Windows, do not pipe the Unix shell installer into PowerShell. Verify Docker Desktop/WSL support against current upstream guidance. Do not install or change the Docker daemon merely to finish a skill edit.
4. Use the user's configured model/provider. Establish an LLM spend cap before a paid run and set `--max-budget`; also choose a per-agent turn cap and a total wall-clock stop plan. The dollar cap is a best-effort estimate checked after responses and can overshoot; it is not a hard billing guarantee. Do not silently increase or reset it.
5. Handle secrets through the configured environment or approved secret mechanism. Check presence without printing values. Do not put credentials in command-line arguments, committed instruction files, reports, or chat. Verify how the installed version persists configuration/instructions and restrict any temporary credential-bearing artifacts accordingly.

Local Docker execution does not mean all data stays on the machine: a hosted LLM can receive source, requests, evidence and instructions. Use only the provider/data handling already authorized for the material. Cloud scans additionally upload material to Strix infrastructure; require an explicit cloud selection or existing authorization. Do not purchase credits or enable remote telemetry as a fallback.

## Isolate the source and constrain targets

Strix mounts local directory targets writable. For an audit, pass a disposable copy/checkout of the exact revision plus relevant uncommitted changes, excluding secrets, generated/dependency directories and unrelated files. Preserve the user's original checkout. Record what was included/excluded and examine changes made in the copy; never copy them back automatically. An instruction saying "do not edit" is not a read-only mount.

API spec targets can automatically add the hosts declared in the specification to engine scope. Inspect `servers`, external references, Postman environments and resolved URLs first. Make a separate sanitized contract containing only authorized hosts. Do not feed an unreviewed production/third-party contract to a staging scan. Do not allow redirects, linked domains, subdomains, IPs or dependencies to widen the user-authorized boundary.

Prepare a filled scope instruction file in the assessment's intermediate directory. Include:

- Exact allowed hosts/ports, source snapshot, paths and environments; explicit forbidden hosts and paths.
- Test goal, chosen coverage families, applicable roles/tenants and synthetic fixtures.
- Read/test-only intent unless fixes are authorized; allowed effects and cleanup rules.
- No customer-data extraction, persistent access, destructive operations, stress tests, real financial transactions or real notifications outside established scope.
- Conservative traffic limits, permitted concurrency, wall-clock stop, and stop conditions for unexpected errors or impact.
- Evidence requirements: entrypoint/control/sink, reproduction, control case, prerequisites, confidence, actual impact, open proof gaps and per-family coverage.

Instructions guide an autonomous engine; they are not an enforceable network sandbox. If the environment cannot contain the requested effects, use local source analysis/mocked tests and report live testing as blocked. Inspect engine network controls for the installed release before relying on them.

## Command shapes

These are templates, not commands to execute with placeholders. Resolve the target, filled instruction path, scan depth, budget and turn limit from the assessment. Use `-n` for agent execution. Specify depth explicitly: `quick` for focused triage, `standard` for routine work, `deep` only when warranted by the task and budget. Explicit `--scope-mode full` avoids an unintended changed-files-only first audit.

```text
strix -n -t <isolated-source-path> --scope-mode full --scan-mode standard --max-budget <usd-cap> --max-turns <per-agent-cap> --instruction-file <filled-scope-file>

strix -n -t <isolated-source-path> -t <authorized-staging-url> --scope-mode full --scan-mode standard --max-budget <usd-cap> --max-turns <per-agent-cap> --instruction-file <filled-scope-file>

strix -n -t <sanitized-api-spec-path> -t <authorized-api-url> --scan-mode standard --max-budget <usd-cap> --max-turns <per-agent-cap> --instruction-file <filled-scope-file>
```

For a diff review, use `--scope-mode diff --diff-base <verified-base-ref>` and record the exact base/head and changed files. Confirm the diff is nonempty and covers the whole requested change, including relevant working-tree changes. Do not assume `origin/main`, use the current branch's own HEAD as the base, or report a diff run as a whole-app audit.

Launch with a tool that returns a controllable process/session and captures logs; poll with bounded waits and keep the user informed. Stop only the scan process and its resources when limits or scope violations occur; do not kill unrelated containers. The parent assistant remains responsible for scope, secrets, and claims despite Strix's internal agent orchestration.

## Read and validate results

At the inspected revision, runs write under `strix_runs/<run-name>/` relative to the chosen working directory. Read `penetration_test_report.md`, `vulnerabilities.json`, individual `vulnerabilities/*.md`, `run.json`, and `coverage.json` when present. CSV and SARIF are available for downstream workflows; their presence is not proof of comprehensive coverage.

Headless OSS exit semantics:

- `0`: no finding that fails the chosen threshold in the analyzed portion.
- `1`: fatal execution/configuration error.
- `2`: findings meeting the threshold; do not treat this as an infrastructure failure.

With `--fail-on`, lower-severity findings still exist in artifacts. A budget/turn-limited or early-wrapped run can appear clean; inspect run status, usage/cost, coverage, report limitations and logs together. Even `completed` can follow an early warning-triggered wrap-up. Record absent/unreadable artifacts as gaps, and never infer "zero vulnerabilities" from them.

Review PoCs as untrusted executable code and revalidate safely against the right revision where feasible. Check affected roles, reachable routes, severity and actual controls. Merge root-cause duplicates across runs while retaining every independently affected location and proof state. Use [reporting.md](reporting.md) for the consolidated report.

## Resume and update

For engine resume, verify the named run has readable metadata and saved agent state, belongs to the authorized target, and still points to the correct source. Scope/account/environment changes may require a fresh run. Resume from the same assessment working directory:

```text
strix -n --resume <existing-run-name> --max-budget <approved-total-run-cap> --max-turns <per-agent-cap>
```

Do not combine `--resume` with `-t`. Check installed-version budget accounting before resuming; treat already-spent cost as consumed, not as a new free allowance. If saved state is missing, start a separately named assessment/run and link previous evidence rather than claiming the engine resumed.

When developing this skill further, retain original local additions, inspect upstream changes since the pinned revision, update only relevant CLI/workflow facts, and change the revision marker after validation. Upstream permission, billing and cloud defaults do not override the user's scope. Do not auto-update the engine or launch scans as part of editing the skill.
