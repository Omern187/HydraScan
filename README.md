# HydraScan

A native review runner and multi-agent skill for finding logic bugs, broken workflows, and security vulnerabilities in apps and websites, with evidence validation and coverage tracking.

HydraScan uses its own Python standard-library runner to inventory source, prepare a bounded text snapshot, surface static candidates, run explicitly selected checks and save review artifacts. A coding agent coordinates complementary reviewers, independently challenges consequential findings and produces a single report with evidence and remaining gaps. It works without a separate scanner engine.

## What it reviews

- **Functional correctness:** calculations, state transitions, imports/exports, concurrency, persistence, startup failures, errors and recovery.
- **Input handling:** query, command and template injection, XSS, SSRF, paths, files, archives and parser boundaries.
- **Identity and trust:** authentication, authorization, tenant isolation, sessions, data exposure, API contracts and native bridges.
- **Runtime and distribution:** alternate launchers, release assets, dependencies, resource limits, deployment configuration and Electron boundaries.

The workflow applies to source review, disposable local tests, authorized staging assessments, finding triage and requested remediation. The runner needs Python 3.10+ and no third-party packages. Semantic review uses the host coding agent; the CLI alone does not launch AI agents or autonomously discover every kind of defect.

## Install

In Codex, ask the skill installer:

```text
Use $skill-installer to install the skill from Omern187/HydraScan at skills/hydrascan.
```

The installable skill is [skills/hydrascan](skills/hydrascan). For manual installation, copy that folder into your skills directory as `hydrascan` (normally `~/.codex/skills/hydrascan`, or `$CODEX_HOME/skills/hydrascan` when configured). The skill entrypoint is [SKILL.md](skills/hydrascan/SKILL.md).

The installed skill is available on the next turn. Multi-agent execution requires a host that supports delegation; otherwise the applicable review lanes run sequentially and that limitation is reported. No Docker, separate provider account or API key is required by the native runner.

## Run the native CLI

From a checkout of this repository:

```text
python skills/hydrascan/scripts/hydrascan.py doctor
python skills/hydrascan/scripts/hydrascan.py scan /path/to/app --output /path/to/new-run
python skills/hydrascan/scripts/hydrascan.py collect /path/to/new-run
```

Use a new run directory outside the reviewed source. For an installed skill, use the script under that skill's installed directory. `scan` creates inventory, candidates, check outcomes, a 32-family coverage ledger, a Markdown report and a continuation checkpoint. `collect` refreshes saved summaries while preserving manual notes; it does not re-test or scan changed source.

Application commands execute only when supplied through `--checks /path/to/checks.json`. For example:

```json
[
  {
    "name": "unit tests",
    "argv": ["python", "-m", "unittest", "discover", "-s", "tests", "-v"],
    "timeout": 60
  }
]
```

Checks run sequentially in the snapshot with argument arrays and no shell. Inspect the code and selected commands first: the snapshot is **not an OS/network sandbox**, and check processes can access the host environment, filesystem and network. Use an appropriately contained disposable environment for untrusted execution. See [native runner details](skills/hydrascan/references/engine.md).

## Use

Review the current project:

```text
Use $hydrascan to review this app for logic bugs, broken workflows and security vulnerabilities. Use complementary agents, reproduce important findings with synthetic data, and save findings, coverage and a continuation checkpoint.
```

Review a GitHub revision:

```text
Use $hydrascan to review owner/repository from GitHub. Pin the current main commit and use an isolated checkout of that revision. Review imports, exports, authorization and asynchronous state, and report tested paths and remaining gaps.
```

Continue an existing assessment:

```text
Use $hydrascan to continue the assessment from review-state.md. Verify the source revision, resume open coverage and candidates, and independently challenge consequential findings.
```

Apply fixes when desired:

```text
Use $hydrascan to fix the confirmed findings in the saved report. Patch the root causes and verify the intended behavior with meaningful regression checks.
```

## How the agents work

| Role | Responsibility |
| --- | --- |
| Coordinator | Pins the revision and scope, inventories entrypoints, assigns coverage, merges evidence and tracks gaps. |
| Logic reviewer | Looks for wrong results, broken journeys, races, stale state, persistence failures and bad recovery. |
| Input reviewer | Traces untrusted input into interpreters, renderers, files, parsers and outbound requests. |
| Identity reviewer | Compares roles and tenants across reads, writes, exports, jobs and API/IPC boundaries. |
| Runtime reviewer | Checks startup variants, protocol handling, dependencies, resource limits and distribution boundaries. |
| Independent validator | Attempts to reproduce or disprove consequential findings from another reviewer. |

Roles are scheduled within the host's actual limits. For example, four total slots allow a coordinator and three reviewers at once; runtime work and independent validation can use later waves. The coordinator can own a lane when the team is small.

Reviewers receive different angles, the same pinned source, and private test resources. They do not receive another discoverer's conclusions during initial discovery. Shared mutable checks are coordinated so that accidental test interference is not mistaken for a product bug.

The coordinator assigns every requested coverage family and critical journey an owner. A completed agent task or a unanimous opinion is not proof of complete coverage. See the [multi-agent workflow](skills/hydrascan/references/multi-agent-review.md).

## Evidence and deliverables

The report separates functional defects, security vulnerabilities and hardening observations. Findings use explicit proof states:

- `dynamic-confirmed`: observed through the tested runtime or component, with substitutions disclosed.
- `source-confirmed`: established by a complete reachable source trace.
- `candidate`: plausible, with a named evidence or product-intent gap.
- `hardening`: an improvement without an established exploitable defect.

Each accepted finding records the source/build, preconditions, expected versus observed behavior, impact, reproduction or trace, controls and proposed fix. The report also records checked and untested paths. A continuation checkpoint preserves scope, agent ownership, evidence, resources and open work.

Important probes include out-of-order file loads, generated artifact inspection, failures hidden by success messages, special object keys, streamed Unicode, encoded identifiers, rejected imports and concurrent shared-file writes. Select probes that match the actual architecture. Passing existing tests does not clear untested failure paths, and a passing bug-demonstration script does not verify a fix.

## What the runner establishes

Local Python assignment-flow and JavaScript/TypeScript/HTML lexical signals are candidates requiring review of reachability, controls and impact. Triage includes composed queries, variable path segments, TAR extraction, evaluator aliases and outbound URL calls. Ownership/tenant questions are saved separately in `security-review-tasks.json`; they require semantic review and controlled role comparisons. Comments and constant HTML are distinguished from executable/user-derived sinks in the recognized source forms. See [cybersecurity validation](skills/hydrascan/references/security-validation.md). Passing or failing a process check is execution evidence, not proof of a vulnerability or a clean application. The preliminary coverage ledger stays `not-started` or `partial` until reviewers supply relevant evidence.

The text snapshot excludes symlinks, dependency/Git directories, known secret files, binaries and oversized files. Inspect the inventory for actual exclusions. Those omissions, missing runtime artifacts and untested deployed builds remain coverage gaps. Filename filtering does not guarantee that included code contains no secrets; inspect and redact reports and keep raw logs private.

HydraScan does not install project dependencies, auto-run discovered commands, perform built-in HTTP scans, call hosted model providers or upload source. Host agents can test authorized local/staging behavior with available tools and incorporate the evidence into the same assessment.

## Repository contents

```text
README.md
skills/hydrascan/
  SKILL.md
  agents/openai.yaml
  scripts/hydrascan.py
  scripts/hydrascan_source.py
  references/
    behavioral-probes.md
    coverage.md
    functional-bugs.md
    multi-agent-review.md
    reporting.md
    security-validation.md
    engine.md
    provenance.md
tests/
  test_native_runner.py
  test_source_review.py
  test_source_regressions.py
```

This repository contains the native runner, source triage, review instructions, UI metadata and regression tests. Private application reports, credentials and generated application binaries are not included.

To test HydraScan itself from the repository root:

```text
python -m unittest discover -s tests -v
```

These tests verify the runner and source triage, including controls and reviewer-discovered parser regressions; they do not assess another application's security.

## Scope

Active testing uses the established authorized targets and effects, preferably disposable local instances or staging with synthetic data. A review request does not authorize production changes, additional hosts, paid/cloud runs or external reporting. The final report states actual coverage and remaining gaps; HydraScan does not guarantee discovery of every vulnerability or certify compliance.

Historical inspiration and upstream credits are preserved in the [provenance reference](skills/hydrascan/references/provenance.md). They are not runtime dependencies. HydraScan has its own runner, functional probes, complementary-agent coordination and resumable review records.

Current workflow revision: **2026-10-10.8**.
