# NETRA — AI‑Driven OSINT Orchestration Engine

> Lightweight, composable OSINT orchestration & reporting engine for Kali/Dev environments.

**Repository layout (what's in this directory)**

* `netra.py` — Main orchestration engine. Accepts an initial target (domain/username/ip/email/phone), uses an "AI brain" to create task plans, runs local OSINT tools, pivots, and generates a final report (MD/HTML/PDF/JSON).
* `phone-osint.py` — Phone number OSINT helper (Numverify/AbstractAPI/IPQS/Twilio integrations). Called by `netra.py` when the target is a phone number. Outputs JSON.
* `gmail-osint.py` — GHunt wrapper to fetch Gmail-related OSINT (photos, maps, profile links). Produces a normalized `ghunt_final_*.json` envelope consumable by `netra.py`.
* `report_template.css` — Optional CSS used when generating HTML/PDF reports.
* `workspaces/` — Sample/empty workspace directory where run-specific workspaces and outputs are created.

---

## Quick TL;DR — Get running in 5 minutes

1. Create a Python virtualenv and activate it:

```bash
python3 -m venv venv
source venv/bin/activate
```

2. Install Python dependencies:

```bash
pip install -r requirements.txt
```

3. Install GHunt (recommended via pipx) and log in:

```bash
pip install pipx
pipx install ghunt
# or: pipx run -- ghunt login
ghunt login
```

4. Export your Gemini / 3rd-party API keys (example):

```bash
export GEMINI_API_KEY="your_gemini_key_here"
export NUMVERIFY_API_KEY="your_numverify_key"
export ABSTRACTAPI_KEY="your_abstractapi_key"
export IPQS_API_KEY="your_ipqs_key"
export TWILIO_SID="your_twilio_sid"
export TWILIO_TOKEN="your_twilio_token"
```

5. Run NETRA:

```bash
python3 netra.py
# follow the interactive prompts (target, goal, report format)
```

---

## Features

* AI-powered task planning + pivoting (uses Google Gemini when configured)
* Orchestrates local Kali CLI OSINT tools (theHarvester, whois, nslookup, sherlock, photon, dmitry, spiderfoot, dirb, finalrecon, emailharvester, email2phonenumber, metagoofil, etc.)
* Phone-specific OSINT via `phone-osint.py` (normalization, multiple API lookups, web evidence collection)
* Gmail-specific OSINT via GHunt wrapper `gmail-osint.py` with robust URL and Maps extraction
* SQLite backend to persist discovered artifacts
* Outputs: Markdown / HTML / PDF / JSON reports and raw tool outputs
* Safe fallbacks when AI is unavailable (deterministic report)

---

## Detailed usage

### `netra.py` (main)

Run interactively:

```bash
python3 netra.py --api-key "$GEMINI_API_KEY"
```

You will be prompted for:

* initial target (domain, username, ip, email, phone)
* investigation goal (plain English)
* report format (`md`, `html`, `pdf`, `json`)

Behavior notes:

* If the initial target looks like a phone number (E.164-ish), NETRA will create a deterministic `phone-osint` task and call `phone-osint.py --json <number>`.
* If the initial target is an email address, NETRA will call `gmail-osint.py` (which in turn calls GHunt) and ingest the returned envelope JSON.
* NETRA caches tool outputs, stores raw outputs to the `tool_results` DB table and sanitized artifacts to tables like `domains`, `hosts`, `contacts`, `profiles`, `breaches`, and `phone_results`.

### `phone-osint.py`

This file is a standalone phone OSINT helper. Example usage:

```bash
python3 phone-osint.py "+1 202-555-0123" --json --numverify-key $NUMVERIFY_API_KEY --max-results 10
```

Expected features implemented by the helper:

* Normalize to E.164 (uses `phonenumbers`)
* Optional enrich via Numverify, AbstractAPI, IPQS, Twilio Lookup
* Web evidence scraping (googlesearch + page scraping)
* Structured JSON output with `number_e164`, `country`, `carrier`, `line_type`, `web_results`, `confidence`

NETRA calls `phone-osint.py --json <number>` and expects strict JSON back. The NETRA engine sanitizes and validates the received phone JSON before storing it.

### `gmail-osint.py` (GHunt wrapper)

Example:

```bash
python3 gmail-osint.py soumadeeppal33@gmail.com --json --follow-redirects --download-photos
```

What it does:

* Runs `ghunt email <target> --json <outfile>`
* Loads the raw GHunt JSON
* Extracts URLs robustly (regex), detects photo candidates, maps/profile links, display name & location hints
* Optionally resolves short links (via `requests`) to find canonical Maps links
* Writes `ghunt_final_<target>_<ts>.json` and prints the normalized envelope for NETRA to ingest

Important: GHunt must be installed and configured (see GHunt docs). `gmail-osint.py` is a thin wrapper that normalizes GHunt output for NETRA.

---

## Requirements

See `requirements.txt` for the full Python dependency list. Key packages:

* `google-generativeai` (optional — Gemini integration for AI planning & report synthesis)
* `markdown2`, `weasyprint` (for HTML/PDF report generation)
* `requests`, `beautifulsoup4`, `lxml` (web scraping & redirection)
* `phonenumbers` (phone normalization)
* `googlesearch-python` (optional — web search helper)
* `tld`, `python-dotenv`, `pydantic`, `langchain` (optional augmentation)

System packages (Debian/Kali) required for PDF generation and some tools:

```bash
sudo apt update
sudo apt install -y build-essential python3-dev python3-venv libffi-dev libssl-dev libxml2-dev libxslt1-dev zlib1g-dev \
  libcairo2 libcairo2-dev libpango1.0-0 libpangocairo-1.0-0 libgdk-pixbuf2.0-0 shared-mime-info libjpeg-dev
```

Also install GHunt via `pipx` (recommended):

```bash
pip install pipx
pipx install ghunt
ghunt login
```

Some Kali CLI OSINT tools are expected to be present (installable via apt): `theharvester`, `dmitry`, `photon`, `emailharvester`, `finalrecon`, `spiderfoot`, `dirb`, `metagoofil`, `sherlock`, etc. You can install them via:

```bash
sudo apt update && sudo apt install theharvester dmitry photon dirb metagoofil
# spiderfoot may be available as spiderfoot or via pip/pipx per its docs
```

---

## Configuration & environment variables

Recommended environment variables (export in shell or use a `.env` file and load with `python-dotenv`):

```bash
GEMINI_API_KEY=...
NUMVERIFY_API_KEY=...
ABSTRACTAPI_KEY=...
IPQS_API_KEY=...
TWILIO_SID=...
TWILIO_TOKEN=...
```

* `GEMINI_API_KEY` — required to enable the AI brain (task planning and report synthesis). If missing NETRA will run in limited/deterministic mode.
* Phone API keys are optional but improve phone enrichment reliability.

**Security note:** Keep API keys out of the repository. Use environment variables or secret managers.

---

## How NETRA stores data

* Uses an on-disk SQLite DB per workspace (file: `workspaces/<target>_<ts>/data.db`).
* Tables include: `domains`, `hosts`, `contacts`, `profiles`, `breaches`, `tool_results`, `phone_results`.
* Raw tool outputs are saved in `tool_results` for auditability. Cleaned, validated artifacts are saved to other tables and used when synthesizing the final report.

---

## Report generation

* NETRA synthesizes a Markdown report using the AI (when available) or a deterministic fallback.
* Outputs are written to the workspace:

  * `report.md` (Markdown)
  * `report.html` (HTML, if `markdown2` available)
  * `report.pdf` (PDF via `weasyprint`, if available)
  * `report.json` (raw DB dump, when `json` format requested)

The `report_template.css` is applied to HTML/PDF outputs if present.

---

## Troubleshooting & common issues

### GHunt reports no maps/profile link but `ghunt` CLI shows it

* Ensure you run the wrapper with `--follow-redirects` to expand short map links.
* Ensure GHunt is authenticated (`ghunt login`) before running the wrapper.
* Inspect the raw `ghunt_*.json` file to see whether GHunt emitted the map/profile entry.

### `ModuleNotFoundError: No module named 'tld'` or other missing Python deps

* Install the missing package in your virtualenv or system Python: `pip install tld`.
* Use the `requirements.txt` and follow the setup steps to avoid individual misses.

### AI returns malformed JSON or quota errors (429)

* Check `GEMINI_API_KEY` and quota usage. If you hit rate limits, either pause or switch to the deterministic fallback mode.
* The engine tolerates missing AI by returning deterministic reports.

### CLI tools returning usage/argparse errors (e.g., `linkedin2username` missing flags)

* NETRA attempts to detect tool usage errors and treat them as non-actionable warnings. If a tool requires specific flags (like a company), avoid invoking it for incompatible target types.

---

## Extending NETRA

* Add new tool wrappers by implementing a `_run_tool(tool, target)` branch and a corresponding `_parse_output(tool, target, output)` parser that returns structured findings.
* When adding external helpers (like `phone-osint.py` or `gmail-osint.py`), ensure they support a `--json` output mode that NETRA can parse.
* Keep AI prompts small and grounded: pass only essential, factual evidence to avoid hallucination.

---

## Legal / Ethical / Operational notes

* **Only run NETRA against systems or accounts you are authorized to assess.** Unauthorized scanning, data exfiltration, or impersonation is illegal and unethical.
* Respect privacy and terms of service for third-party APIs (GHunt, Numverify, AbstractAPI, IPQS, Twilio, etc.).
* When using internet search scraping, obey site `robots.txt` and rate limits.

---

## Roadmap & ideas for future work

* GUI / Web dashboard with multi-tenant workspaces
* API for enterprise ingestion (webhooks, streaming results)
* SIEM/SOC connectors (forward findings to Splunk / Elastic / Azure Sentinel)
* Built-in scheduling / continuous monitoring for brand protection
* Hardened evidence chain (signed reports, verifiable hashes)

---

## Contributing

1. Fork the repo
2. Create a feature branch
3. Run tests / linting
4. Open a PR with a clear description

Please follow responsible disclosure if you add checks that might reveal vulnerabilities.

---

## License

Choose an appropriate license for your project (MIT, Apache-2.0, etc.). This README does not include a license file — add one to the repo root.

---

If you want, I can:

* Produce a `setup.sh` that automates system deps + venv setup + pip install (safe, interactive), or
* Create a `CONTRIBUTING.md` and `ISSUE_TEMPLATE.md` for your GitHub repo.

Tell me which next and I will drop it in the repo.
