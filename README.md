# BIGFIX- Microsoft Agent Framework PyPI Supply Chain Attack Detection

Detect indicators from the malicious PyPI releases of `agent-framework` **1.26.1** and **1.26.2** on Windows, Linux, and macOS. The malicious wheels added a Python startup hook that could run without an application importing the framework. [PyPA advisory PYSEC-2026-4388](https://osv.dev/vulnerability/PYSEC-2026-4388)

## Use

1. Download [Agent_Framework_PyPI_Compromise_Analysis.bes](Agent_Framework_PyPI_Compromise_Analysis.bes) and import it into a BigFix custom site.
2. Review site subscription scope before activating. Start with test systems.
3. Read **IOC Found-**. `TRUE - <path>` lists matching artifacts. `FALSE` means the client found no matching artifacts in the checked locations.

The single property runs every six hours and reads files without starting Python or pip. macOS checks include Python.org frameworks, Homebrew library paths and versioned Python kegs, system and per-user Python library paths, and .venv directories directly under user home directories.

## Indicators checked by the Analysis

| Check | Exact indicator | Where the Analysis checks |
| --- | --- | --- |
| Installed distribution metadata | PyPI package `agent-framework` at `1.26.1` or `1.26.2` | `METADATA` in the two versioned `agent_framework-*.dist-info` directories |
| 1.26.1 startup hook and payload filenames | `agent_framework_meta.pth`, `agent_framework_meta/_telemetry.py` | Package directory |
| 1.26.2 startup hook and payload filenames | `af_runtime_diag.pth`, `af_runtime_diag.py` | Package directory |
| 1.26.1 telemetry RECORD digest | `OfoynyqT9zSwu49a2yA-ozMdGuR5gypQFaVMsXqr1mM` | Matching `agent_framework_meta/_telemetry.py` row in the distribution's `RECORD` |
| 1.26.1 startup hook RECORD digest | `IfKOhRehD_5DH41o9YdcheykABrm0RgyKwpBhzmY614` | Matching `agent_framework_meta.pth` row in the distribution's `RECORD` |
| 1.26.1 startup hook SHA-256 | `21f28e8517a10ffe431f8d68f5875c85eca4001ae6d118322b0a41873998eb5e` | Top-level `.pth` files in the package directory |
| 1.26.2 startup hook SHA-256 | `325e7e9f0ec94e41ad1a1b7a3f18a6b8b5bffece2e2b97b8d3369eb967452f93` | Top-level `.pth` files in the package directory |
| 1.26.1 telemetry module SHA-256 | `39fa329f2a93f734b0bb8f5adb203ea3331d1ae479832a5015a54cb17aabd663` | `.py` files in `agent_framework_meta` |
| 1.26.1 modified initializer SHA-256 | `c275ccbe520ef3c0f02dc6a35389e427f9f1b4e0b12e140cd7bf7179ce143f02` | `.py` files in `agent_framework_meta` |
| 1.26.1 wheel SHA-256 | `d27fa34414e6201d5e03e559ef634f020057554d7b3f4898dd5d7cd3e989e110` | `agent_framework-1.26.1-py3-none-any.whl` in standard user Downloads folders |
| 1.26.2 wheel SHA-256 | `3d20a8bc91351a9a16b6db243b848ceca0206b7a8623b02d2af553a9c9f7e0a9` | `agent_framework-1.26.2-py3-none-any.whl` in standard user Downloads folders |

**Network hunt.** Search proxy or EDR telemetry for `webhook[.]site/d381fd80-ec62-42ad-8f5c-d1b15103c9bb` where the destination path is visible.

Custom Python prefixes, unlisted virtual environments, WSL from Windows, containers, package caches, and historical CI artifacts require separate coverage. A filename or metadata hit is an indicator. Use endpoint, CI, and network telemetry to determine execution or credential exposure. [JFrog artifact and network indicators](https://research.jfrog.com/post/agent-framework-hijack/#indicators-of-compromise)
