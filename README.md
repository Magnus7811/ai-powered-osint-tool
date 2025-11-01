# NETRA — AI‑Driven OSINT Orchestration Engine

> **Lightweight, composable OSINT orchestration & reporting engine for Kali/Dev environments.**

---

## Repository Structure

- **`netra.py`**: Main orchestration engine. Accepts an initial target (domain, username, IP, email, or phone), uses an "AI brain" for task planning, executes local OSINT tools, pivots, and generates final reports (Markdown/HTML/PDF/JSON).
- **`phone-osint.py`**: Phone number OSINT helper (integrates Numverify, AbstractAPI, IPQS, Twilio). Invoked by `netra.py` for phone targets. Outputs normalized JSON.
- **`gmail-osint.py`**: GHunt wrapper for Gmail-related OSINT (photos, maps, profile links). Produces normalized envelopes for `netra.py`.
- **`report_template.css`**: Optional CSS for styling HTML/PDF reports.
- **`workspaces/`**: Workspace directory for run-specific outputs and artifacts.

---

## Quick Start

### 1. Set Up Virtual Environment

```bash
python3 -m venv venv
source venv/bin/activate
```

### 2. Install Python Dependencies

```bash
pip install -r requirements.txt
```

### 3. Install GHunt

```bash
pip install pipx
pipx install ghunt
ghunt login
```

### 4. Export API Keys

```bash
export GEMINI_API_KEY="your_gemini_key_here"
export NUMVERIFY_API_KEY="your_numverify_key"
export ABSTRACTAPI_KEY="your_abstractapi_key"
export IPQS_API_KEY="your_ipqs_key"
export TWILIO_SID="your_twilio_sid"
export TWILIO_TOKEN="your_twilio_token"
```

### 5. Run NETRA

```bash
python3 netra.py
# Follow interactive prompts (target, goal, report format)
```

---

## Features

- **AI-Powered Planning & Pivoting**: Uses Google Gemini for intelligent task orchestration (if API key provided).
- **Integration with Kali OSINT Tools**: Orchestrates tools like theHarvester, whois, nslookup, sherlock, photon, dmitry, spiderfoot, dirb, finalrecon, emailharvester, email2phonenumber, metagoofil, and more.
- **Phone OSINT**: `phone-osint.py` for phone number normalization, multi-API enrichment, and web evidence collection.
- **Gmail OSINT**: `gmail-osint.py` wraps GHunt for Gmail artifact extraction and normalization.
- **SQLite Backend**: Persists discovered artifacts for auditability and reporting.
- **Flexible Report Generation**: Output in Markdown, HTML, PDF, or JSON.
- **Resilient Fallbacks**: Deterministic, reliable operation even when AI services are unavailable.

---

## Detailed Usage

### `netra.py` (Main Orchestrator)

Run interactively:

```bash
python3 netra.py --api-key "$GEMINI_API_KEY"
```

- **Prompts for**:
  - Target (domain, username, IP, email, phone)
  - Investigation goal (plain English)
  - Report format (`md`, `html`, `pdf`, `json`)
- **Automatic Tool Selection**:
  - Phone targets: Invokes `phone-osint.py --json <number>`
  - Email targets: Invokes `gmail-osint.py` (requires GHunt)
- **Data Persistence**: 
  - Caches tool outputs, stores raw/sanitized results in SQLite tables like `domains`, `hosts`, `contacts`, `profiles`, `breaches`, and `phone_results`.

### `phone-osint.py`

Standalone helper for phone number intelligence:

```bash
python3 phone-osint.py "+1 202-555-0123" --json --numverify-key $NUMVERIFY_API_KEY --max-results 10
```

- **Features**:
  - E.164 normalization via `phonenumbers`
  - Multi-API enrichment (Numverify, AbstractAPI, IPQS, Twilio)
  - Web evidence via googlesearch + scraping
  - Strict JSON output for ingestion by NETRA

### `gmail-osint.py` (GHunt Wrapper)

Example:

```bash
python3 gmail-osint.py target@gmail.com --json --follow-redirects --download-photos
```

- **Features**:
  - Runs and normalizes `ghunt email` output
  - Extracts URLs, photos, maps, profiles, display names, and location hints
  - Optionally resolves short links
  - Outputs a normalized JSON envelope for NETRA

---

## Requirements

- **Python dependencies**: See `requirements.txt`. Key packages:
  - `google-generativeai` (optional, for AI features)
  - `markdown2`, `weasyprint` (for HTML/PDF reports)
  - `requests`, `beautifulsoup4`, `lxml` (scraping)
  - `phonenumbers`, `tld`, `python-dotenv`, `pydantic`, `langchain` (optional)
- **System packages** (Debian/Kali, for PDF and tools):

  ```bash
  sudo apt update
  sudo apt install -y build-essential python3-dev python3-venv libffi-dev libssl-dev libxml2-dev libxslt1-dev zlib1g-dev \
    libcairo2 libcairo2-dev libpango1.0-0 libpangocairo-1.0-0 libgdk-pixbuf2.0-0 shared-mime-info libjpeg-dev
  ```

- **OSINT Tools** (install via apt):

  ```bash
  sudo apt update && sudo apt install theharvester dmitry photon dirb metagoofil
  # spiderfoot may require pip/pipx per its docs
  ```

- **GHunt**: Install via `pipx` and authenticate:

  ```bash
  pip install pipx
  pipx install ghunt
  ghunt login
  ```

---

## Configuration & Environment

Recommended environment variables (export or use `.env`):

```bash
GEMINI_API_KEY=...
NUMVERIFY_API_KEY=...
ABSTRACTAPI_KEY=...
IPQS_API_KEY=...
TWILIO_SID=...
TWILIO_TOKEN=...
```

- `GEMINI_API_KEY` — (Optional) Enables AI task planning/reporting. Without it, NETRA runs deterministically.
- API keys for phone enrichment are optional but recommended.

> **Security:** Never commit API keys. Use environment variables or secret managers.

---

## Data Storage

- **SQLite**: Each workspace has its own database (`workspaces/<target>_<ts>/data.db`).
- **Tables**: `domains`, `hosts`, `contacts`, `profiles`, `breaches`, `tool_results`, `phone_results`.
- **Raw & Cleaned Data**: Raw tool outputs are retained for auditing; sanitized artifacts are used in reports.

---

## Report Generation

- **Formats**: Markdown, HTML, PDF, JSON
- **Location**: Saved in the workspace directory as `report.md`, `report.html`, `report.pdf`, and/or `report.json`.
- **Styling**: `report_template.css` is used for HTML/PDF if present.
- **AI Synthesis**: Uses AI for advanced synthesis when available, otherwise falls back to deterministic reporting.

---

## Troubleshooting

### GHunt Issues

- Ensure `--follow-redirects` is used for map/profile link extraction.
- Run `ghunt login` before using the wrapper.
- Check raw `ghunt_*.json` for expected entries.

### Missing Python Modules

- Install missing dependencies with `pip install <module>`.
- Use `requirements.txt` to avoid omissions.

### AI Errors (Malformed JSON/Quota)

- Check `GEMINI_API_KEY` validity and usage.
- If rate-limited, NETRA will fall back gracefully.

### CLI Tool Usage Errors

- NETRA attempts to handle tool-specific argument errors gracefully.
- Avoid invoking incompatible tools for given target types.

---

## Extending NETRA

- **New Tool Integration**: Add a `_run_tool(tool, target)` branch and a `_parse_output(tool, target, output)` parser.
- **External Helpers**: Ensure they support a `--json` output mode.
- **AI Prompting**: Keep prompts concise and evidence-based to minimize hallucination.

---

## Legal, Ethical & Operational Notes

- **Authorization**: Only use NETRA on systems/accounts you are permitted to assess.
- **Privacy**: Respect privacy and API terms of use.
- **Web Scraping**: Obey `robots.txt` and site rate limits.

---

## Roadmap

- Web dashboard with multi-tenant workspaces
- API endpoints for enterprise integration
- SIEM/SOC connectors (Splunk, Elastic, Sentinel, etc.)
- Continuous monitoring/scheduling
- Evidence chain hardening (signed, verifiable reports)

---

## Contributing

1. Fork the repository
2. Create a feature branch
3. Run tests and linting
4. Open a PR with a clear description

> **Note:** For checks that may expose vulnerabilities, please follow responsible disclosure practices.

---

## License

Choose and add an appropriate license file (e.g., MIT, Apache-2.0) to the repository root.

---

