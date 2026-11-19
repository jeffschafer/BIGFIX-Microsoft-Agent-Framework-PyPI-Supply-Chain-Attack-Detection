# BIGFIX- Compromised Microsoft Python Agent-Framework (Supply Chain Attack) Detection

Detect indicators from the malicious PyPI releases of `agent-framework` **1.26.1** and **1.26.2** on Windows and Linux. The malicious wheels added a Python startup hook that could run without an application importing the framework. [PyPA advisory PYSEC-2026-4388](https://osv.dev/vulnerability/PYSEC-2026-4388)

## Use

1. Download [Agent_Framework_PyPI_Compromise_Analysis.bes](Agent_Framework_PyPI_Compromise_Analysis.bes) and import it into a BigFix custom site.
2. Review site subscription scope before activating. Start with test systems.
3. Read **IOC Found-**. `TRUE - <path>` lists matching artifacts. `FALSE` means the client found no matching artifacts in the checked locations.

The single property runs every six hours and reads files without starting Python or pip.

| Indicator | Checked locations |
| --- | --- |
| Affected package name and exact versions, known startup-hook and payload filenames, selected installed-file hashes, and published 1.26.1 RECORD digests | The Windows and Linux package locations listed in the Analysis description |
| SHA-256 of either malicious wheel | Original wheel filenames directly in standard user Downloads folders |
| `webhook[.]site/d381fd80-ec62-42ad-8f5c-d1b15103c9bb` | Hunt in proxy or EDR telemetry where the destination is visible |

Custom Python prefixes, unlisted virtual environments, WSL from Windows, containers, package caches, and historical CI artifacts require separate coverage. A filename or metadata hit is an indicator. Use endpoint, CI, and network telemetry to determine execution or credential exposure. [JFrog artifact and network indicators](https://research.jfrog.com/post/agent-framework-hijack/#indicators-of-compromise)
