# Host support

HydraScan has one shared `SKILL.md`, runner and reference set. Host-specific installation and tool availability affect how the workflow runs; they do not change the evidence requirements or authorized scope.

| Host | Skill location / installation | Invocation |
| --- | --- | --- |
| Codex | Copy the whole skill to `~/.codex/skills/hydrascan`, or use the configured skills directory. | `$hydrascan` |
| Claude Code | Copy the whole skill to `~/.claude/skills/hydrascan` for personal use, or `.claude/skills/hydrascan` in the reviewed project. | `/hydrascan` |
| Claude custom Skills | Upload a ZIP containing `hydrascan/SKILL.md` and its supporting files. | Ask Claude to use HydraScan; the host controls discovery and invocation. |

## Claude Code

Download or clone the repository and copy **all of `skills/hydrascan`**, not only `SKILL.md`, into one of the Claude Code locations above. Use a new session to verify discovery, then invoke:

```text
/hydrascan Review this app for bugs and security issues.
Use separate reviewers where available, verify findings,
and save tested paths, remaining gaps and review-state.md.
```

The base CLI needs Python 3.10+. Choose the actual interpreter available on the host (`python`, `python3` or an explicit executable). Resolve `scripts/hydrascan.py` from the installed skill directory; the reviewed app's working directory is not the skill directory. Optional Node/Babel setup remains described in [project-analysis.md](project-analysis.md).

The coordinator owns the inventory, native scan and final report. Use the available Agent/subagent mechanism for scoped review lanes, keeping normal host permissions and model settings. Each task must contain:

```text
Read the installed HydraScan SKILL.md at <absolute skill path>.
Read <lane references> and applicable repository instructions.
Review <source path and pinned revision> within <authorized scope>.
Own <lane, coverage families and critical journeys>.
Use <private scratch path> for permitted tests and evidence.
Do not repeat the coordinator's scan or start another review team.
Return findings, candidates, controls, tested paths and gaps.
```

Separate subagents may start without the parent's conversation and active skill content. Explicitly give them what they need; custom agents can preload skills when configured by the user. Do not create custom agents, change permission settings or enable experimental agent teams merely to run HydraScan. If delegation is unavailable, perform lanes sequentially and disclose that independent agent validation was unavailable.

`agents/openai.yaml` is Codex UI metadata. The shared review instructions do not depend on it. The skill intentionally avoids Claude-only invocation hooks or a forced fork so the same files remain portable and coordination stays in the main session.

## Claude custom-skill upload

From the root of a committed checkout, build a skill-only archive:

```sh
git archive --format=zip --output=hydrascan-skill.zip HEAD:skills
```

This archives the committed skill folder, excluding untracked parser installations and local runs. Commit intended skill changes before rebuilding. The ZIP must have this shape:

```text
hydrascan-skill.zip
└── hydrascan/
    ├── SKILL.md
    ├── scripts/
    ├── references/
    └── agents/
```

Enable code execution where required, then upload through Claude's custom Skills interface. Upload the skill-only ZIP, not GitHub's whole-repository ZIP. Source files for an assessment must be supplied or otherwise accessible within the user's authorized workflow; uploading the skill does not give Claude access to a local repository.

Check actual capabilities before beginning. Review available files, use the native CLI only if Python and filesystem execution are accessible, and record missing runtime or parser prerequisites. Use multiple agents only when the host exposes delegation. Otherwise review sequentially and report the limits. Do not describe a Claude chat source review as a live application assessment.

## Verification and sources

The shared frontmatter and copied skill layout are validated locally, and the CLI is smoke-tested from an isolated Claude-style installation outside the application's working directory. Claude Code and the custom uploader were not available in the development environment for an end-to-end invocation test.

- [Claude Code skills](https://code.claude.com/docs/en/skills): skill paths, `/skill-name` invocation and standard frontmatter.
- [Claude Code subagents](https://code.claude.com/docs/en/sub-agents): separate contexts, skill preloading and tool permissions.
- [Create custom skills](https://support.claude.com/en/articles/12512198-how-to-create-custom-skills): ZIP structure.
- [Use skills in Claude](https://support.claude.com/en/articles/12512180-use-skills-in-claude): upload and code-execution requirements.
