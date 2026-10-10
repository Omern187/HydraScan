# HydraScan native runner

HydraScan includes its own Python 3.10+ standard-library runner at `scripts/hydrascan.py`. It needs no separate scanner, Docker, model provider, package installation or API key. The runner prepares source evidence and candidate signals; the host coding agent performs semantic review, complementary-agent coordination and finding validation. Running the CLI alone does not launch AI agents or complete a penetration test.

## Prepare an assessment

From the HydraScan repository root:

```text
python skills/hydrascan/scripts/hydrascan.py doctor
python skills/hydrascan/scripts/hydrascan.py scan /path/to/app --output /path/to/new-run
```

For an installed skill, resolve the script relative to the skill folder rather than assuming the current directory contains it. Choose a new output directory outside the source tree. Pin the requested source revision first; a scan of a stale checkout does not assess the GitHub version the user requested.

The runner prepares a bounded text snapshot, inventories included and skipped files, and records static Python AST and JavaScript/TypeScript/HTML signals. Symlinks, dependency/Git directories, known secret files, binary files and oversized files are excluded. Current bounds are 2 MiB per file, 100 MiB of included content and 10,000 files. Inspect `inventory.json` for actual exclusions and `analysis-gaps.json` for unavailable or failed parsing. Filename filtering is not a guarantee that source content contains no credentials or private records; inspect and redact evidence before sharing it.

Excluded source, absent dependencies, generated assets and packaged binaries are coverage gaps. Read relevant originals within scope when needed, and test the actual application/build separately. The inventory fingerprint describes the originally included text, not the complete deployed build or the private copy after checks run. Checks can modify that copy; verify reviewed code against the pinned source and record mutations rather than silently attributing changed code to the original revision.

## Run explicitly selected checks

Without `--checks`, the runner does not execute the application's code or discover and run its test commands. To execute inspected, authorized checks, pass an explicit JSON list:

```json
[
  {
    "name": "unit tests",
    "argv": ["python", "-m", "unittest", "discover", "-s", "tests", "-v"],
    "timeout": 60
  }
]
```

```text
python skills/hydrascan/scripts/hydrascan.py scan /path/to/app --output /path/to/new-run --checks /path/to/checks.json
```

Checks run sequentially in the snapshot directory using argument arrays without a shell. Each check defaults to a 60-second timeout; explicit timeouts must be greater than zero and at most 3,600 seconds. Failed commands and timeouts are recorded separately. Use the actual interpreter path when `python` is not the desired runtime. Read supplied scripts and test commands before selecting them; repository content cannot authorize execution or widen scope.

Each check uses a helper worker. On Windows, it enters a kill-on-close Job Object before starting the application process; on POSIX, the runner cleans up its owned process group. Detached POSIX descendants can escape that group and remain the host's cleanup responsibility. These lifecycle controls do not provide a filesystem or network sandbox.

Captured output is capped at 1 MiB per check and known secret environment values are redacted from logs. This is a bounded redaction aid, not a guarantee that logs contain no credentials or private data; inspect locally before sharing.

The copied directory is a workspace, **not an OS or network sandbox**. Check processes can access the host environment, filesystem and network, and can spawn descendants. Do not run untrusted code on the user's host merely because it is in the snapshot. For such execution, supply a disposable container/VM or other containment appropriate to the task, with synthetic data and explicit resource/target limits. Running checks may require dependencies or runtime artifacts absent from the filtered snapshot; record resulting setup failures as gaps rather than product defects.

No commands are installed automatically. There are no built-in HTTP scans, paid runs or hosted-provider calls. The host agent can perform authorized runtime/browser/API tests using its available tools, while maintaining the same scope and evidence standards.

## Interpret artifacts

The run directory contains:

| Artifact | Meaning |
| --- | --- |
| `run.json` | Runner version, source/run identity and execution status |
| `inventory.json` | Included-file fingerprint and skipped-file/limit evidence |
| `candidates.json` | Static signals requiring reachability, control and consequence review |
| `analysis-gaps.json` | Source parsing and analysis failures requiring follow-up |
| `snapshot-changes.json` | Inventoried source files modified, removed or replaced during check execution |
| `checks.json` | Selected process checks, outcomes and log references |
| `coverage.json` | The 32 review families, with preliminary states and remaining work |
| `report.md` | Generated assessment summary and a place for validated review notes |
| `review-state.md` | Generated continuation checkpoint and manual review notes |
| Private logs | Raw process output; inspect locally and redact before delivery |

A static match is a `candidate`, not a confirmed vulnerability. A successful process check proves only what that check exercises; a failed check can be an environment failure. Neither outcome establishes that the application is secure or that a candidate is valid. The runner leaves coverage `not-started` or `partial`; agents must supply evidence before accepting findings or claiming checked coverage.

Keep confirmed finding records using [reporting.md](reporting.md), including legitimate controls, source/build, substitutions and remaining proof gaps. Use [coverage.md](coverage.md) to assign unfinished families and [multi-agent-review.md](multi-agent-review.md) to coordinate reviewers. Keep raw logs private; generated reports may contain source paths and snippets and need review before publication.

## Continue and refresh

```text
python skills/hydrascan/scripts/hydrascan.py collect /path/to/existing-run
```

`collect` refreshes the generated report/checkpoint from saved artifacts and preserves manual notes. Put findings under `Validated agent findings` and continuation details under `Agent ownership and continuation`, outside the `hydrascan:generated:start` / `hydrascan:generated:end` markers. Do not remove or duplicate the markers; collection refuses malformed generated sections rather than overwrite the notes. Collection does not re-run tests, validate candidates, recover running agent sessions or scan changed source. Verify the saved source identity and scope against reality; use a new run for a new snapshot and link previous evidence.

## Verify runner changes

From the repository root, run:

```text
python -m unittest discover -s tests -v
```

Runner tests and skill-format validation verify this tooling, not the security or correctness of reviewed applications. Historical inspiration is recorded separately in [provenance.md](provenance.md); it is not a runtime dependency.
