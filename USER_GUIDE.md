# THE SHOVEL: Operational User Guide (v1.1.0)

## Overview
THE SHOVEL is an automated, multi-threaded OSINT and Attack Surface Mapping framework. It is designed to bridge the gap between technical infrastructure reconnaissance and social engineering intelligence. In a single execution, it maps live subdomains, discovers exposed high-value files, extracts executive personnel data, and compiles the intelligence into a professional Red Team assessment report.

## Core Modules & Execution Pipeline

The framework operates in a strict, sequential pipeline to maximize data correlation and minimize target alerting.

### 1. Pre-Flight Validation
Before initiating any active scanning, the engine validates the target's DNS resolution to confirm the domain is active and discoverable.

### 2. Active Infrastructure Reconnaissance
*   **Header Analysis:** Probes the primary target over HTTP and HTTPS to extract `Server` and `X-Powered-By` headers, identifying the core backend technology stack.
*   **Missing Security Controls:** Audits the presence of essential security headers like `Strict-Transport-Security` and `X-Frame-Options`.

### 3. Passive Enumeration (The Silent Phase)
*   **Certificate Transparency (crt.sh):** Extracts subdomains without sending a single packet to the target's infrastructure.
*   **HackerTarget Fallback:** In the event of an API timeout, the engine automatically routes through secondary intelligence sources to ensure complete mapping.
*   **Google Dork Generation:** Parses the local `dorks.json` library to construct targeted search queries for public file leaks, admin portals, and exposed databases.

### 4. Concurrent Fingerprinting & Fuzzing (The Active Phase)
*   **Mass Fingerprinting:** Utilizes `concurrent.futures` to rapidly probe all discovered subdomains, filtering dead nodes (`Status 404/500`) from live assets.
*   **Smart Baseline Fuzzing:** To combat WAFs and dynamic routing, the engine first establishes a "Soft-404" baseline length by querying a non-existent file. It then fuzzes for high-value exposures (`.env`, `.git/config`, `phpinfo.php`, `server-status`) and automatically rejects any response that matches the baseline length, ensuring zero false positives.

### 5. Identity OSINT (The Human Element)
*   **Hunter.io Integration:** Connects to commercial intelligence databases to extract the names, titles, departments, and valid email addresses of corporate personnel, formatting them for spear-phishing and social engineering attack vectors.

### 6. Automated Reporting Compiler
*   The compiler ingests the raw JSON output and synthesizes an executive-ready Markdown report (`_report_v2.md`). It surgically filters out low-level informational noise (like `robots.txt` exposures) and exclusively highlights **Critical** (Source Code/API leaks) and **High** (Path Disclosure) vulnerabilities.

---

## Installation Requirements

Ensure you are running **Python 3.9+**. 

```bash
git clone https://github.com/Atsukiiii01/The-Shovel.git
cd The-Shovel
pip install -e .
```
*Note: This project strictly utilizes PEP 621 `pyproject.toml` standards. Do not attempt to use `requirements.txt`.*

---

## Command Line Interface (CLI) Guide

Once installed, THE SHOVEL is globally accessible via the `shovel` alias.

### Syntax
`shovel -t <target_domain> [-H <api_key>] [-o <output_format>]`

### Arguments
| Argument | Flag | Required | Description |
| :--- | :--- | :--- | :--- |
| `--target` | `-t` | **Yes** | The primary domain to audit (e.g., `example.com`). |
| `--hunter` | `-H` | No | Your Hunter.io API key. Required to activate the Identity OSINT module. |
| `--output` | `-o` | No | Defines the export format. Options: `json`, `md`, `all`. Defaults to `all`. |

### Example Execution
```bash
# Full execution with Identity OSINT and dual-format exporting
shovel -t example.com -H b0c1d8e... -o all

# Silent/Headless execution for cron-jobs (JSON export only)
shovel -t example.com -o json
```

---

## Operational Security (OpSec)

**1. Data Hygiene:**
THE SHOVEL generates artifacts containing sensitive vulnerability data (`_recon.json`) and localized SQLite tracking databases (`.db`). A strict `.gitignore` is included in this repository. **Do not modify the gitignore.** Committing these artifacts to public version control will expose both you and your target.

**2. Legal Disclaimer:**
This tool transitions from passive OSINT to active fuzzing. Active fuzzing interacts directly with target infrastructure. You must have explicit, written authorization (such as a Bug Bounty program brief or a signed Statement of Work) before pointing THE SHOVEL at a target. The developer assumes no liability for illegal or unauthorized use.