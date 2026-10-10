# HydraScan

A multi-agent skill for finding logic bugs, broken workflows, and security vulnerabilities in apps and websites, with evidence validation and coverage tracking.

HydraScan gives a coding agent a coordinated review workflow: several reviewers examine different boundaries, another reviewer challenges consequential findings, and a coordinator produces a single report with evidence and remaining gaps.

## What it reviews

- **Functional correctness:** calculations, state transitions, imports/exports, concurrency, persistence, startup failures, errors and recovery.
- **Input handling:** query, command and template injection, XSS, SSRF, paths, files, archives and parser boundaries.
- **Identity and trust:** authentication, authorization, tenant isolation, sessions, data exposure, API contracts and native bridges.
- **Runtime and distribution:** alternate launchers, release assets, dependencies, resource limits, deployment configuration and Electron boundaries.

The workflow applies to source review, disposable local tests, authorized staging assessments, finding triage and requested remediation. It can review ordinary bugs without installing a penetration-testing engine.

## Install

In Codex, ask the skill installer:

```text
Use $skill-installer to install the skill from Omern187/HydraScan at skills/hydrascan.
```

The installable skill is [skills/hydrascan](skills/hydrascan). For manual installation, copy that folder into your skills directory as `hydrascan` (normally `~/.codex/skills/hydrascan`, or `$CODEX_HOME/skills/hydrascan` when configured). The skill entrypoint is [SKILL.md](skills/hydrascan/SKILL.md).

The installed skill is available on the next turn. Multi-agent execution requires a host that supports delegation; otherwise the applicable review lanes run sequentially and that limitation is reported.

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

## Strix integration

HydraScan optionally uses [Strix](https://github.com/usestrix/strix) for authorized security testing. Strix installation, Docker, provider configuration and any paid-run budget are separate prerequisites. HydraScan does not bundle or automatically install the engine, purchase credits, or upload source to a cloud scanner.

The integration records the inspected upstream revision and explains isolated execution, artifact interpretation, coverage limitations and resume behavior. See [Strix integration and provenance](skills/hydrascan/references/strix.md).

## Repository contents

```text
README.md
skills/hydrascan/
  SKILL.md
  agents/openai.yaml
  references/
    behavioral-probes.md
    coverage.md
    functional-bugs.md
    multi-agent-review.md
    reporting.md
    strix.md
```

This repository contains reusable review instructions and UI metadata. Private application reports, credentials, generated application binaries and the Strix engine are not included.

## Scope and attribution

Active testing uses the established authorized targets and effects, preferably disposable local instances or staging with synthetic data. A review request does not authorize production changes, additional hosts, paid/cloud runs or external reporting. The final report states actual coverage and remaining gaps; HydraScan does not guarantee discovery of every vulnerability or certify compliance.

HydraScan is an independent adaptation of the [Strix](https://github.com/usestrix/strix) workflow, with additional functional probes, complementary-agent coordination and resumable review records. It is not an official Strix distribution. Upstream Strix is Apache-2.0 licensed; upstream executables and full skill packs are not bundled. The inspected upstream commit is preserved in the skill metadata and provenance reference.

Current workflow revision: **2026-10-10.5**.
