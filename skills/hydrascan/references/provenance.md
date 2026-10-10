# Historical inspiration and credits

The initial HydraScan review instructions were inspired by [usestrix/strix](https://github.com/usestrix/strix), inspected at commit `62b496430da5df5e9e79a190e7af6f92529883a3` on 2026-10-10. The inspected project declared version `1.7.0` and an Apache-2.0 license.

Relevant concepts included asset-aware assessment selection, source-aware discovery, counterevidence and fix verification. HydraScan's instructions are an original adaptation with its own functional probes, complementary-agent coordination, coverage and continuation records. Its native standard-library Python runner is an independent implementation.

HydraScan does not bundle, import, install or invoke the upstream engine or its full skill packs. These links preserve credit and context; they are not setup instructions or execution dependencies. The upstream project's license does not automatically establish a license for HydraScan.

Inspected references:

- [Application review workflow](https://github.com/usestrix/strix/blob/62b496430da5df5e9e79a190e7af6f92529883a3/skills/application-security-testing/SKILL.md).
- [Source-aware discovery](https://github.com/usestrix/strix/blob/62b496430da5df5e9e79a190e7af6f92529883a3/strix/skills/analysis/source_aware_discovery.md).
- [Counterevidence](https://github.com/usestrix/strix/blob/62b496430da5df5e9e79a190e7af6f92529883a3/strix/skills/analysis/counterevidence.md).
- [Fix verification](https://github.com/usestrix/strix/blob/62b496430da5df5e9e79a190e7af6f92529883a3/strix/skills/analysis/fix_verification.md).
