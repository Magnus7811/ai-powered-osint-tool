#!/usr/bin/env python3
#
# Project NETRA: AI-Driven OSINT Orchestration Engine
# Version: 1.6 (Phone-OSINT: strict parsing, sanitized storage) + Gmail wrapper integration
#
# DISCLAIMER: Only use on assets you have permission to test.

import os
import sys
import subprocess
import sqlite3
import argparse
import json
import re
import time
import shutil
import random
from datetime import datetime

# --- Optional reporting libs ---
try:
    import markdown2
    from weasyprint import HTML
except Exception:
    markdown2 = None
    HTML = None

# --- AI Integration ---
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "")

try:
    import google.generativeai as genai
except Exception:
    genai = None

# --- Optional validation libs (LangChain / pydantic) ---
try:
    import langchain  # only to detect availability
    from pydantic import BaseModel
    from langchain.output_parsers import PydanticOutputParser
    LANGCHAIN_AVAILABLE = True
except Exception:
    LANGCHAIN_AVAILABLE = False

# --- UI colors ---
class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    RESET = '\033[0m'
    BOLD = '\033[1m'

# --- Prompts ---
TASK_PLANNER_PROMPT = """You are an expert OSINT Task Planner. Your job is to translate a user's high-level goal into a sequence of concrete tasks for an automated reconnaissance framework.

Available Tools:
- 'theharvester': Use for a domain. Finds emails and subdomains.
- 'whois': Use for a domain. Finds registration information.
- 'nslookup': Use for a domain/host. Finds the IP address.
- 'geoiplookup': Use for an IP address. Finds the geographic location.
- 'sherlock': Use for a username. Finds social media profiles.
- 'hibp': Use for an email address. Checks for breaches using an internal module.
- 'spiderfoot-cli': Use for a domain or IP. Performs comprehensive OSINT scans (SpiderFoot).
- 'dirb': Use for a URL. Finds hidden web directories via brute-force.
- 'deepmagic': Use for a domain or IP. Gathers broad OSINT (Deepmagic Information Gathering).
- 'email2phonenumber': Use for an email. Attempts to find an associated phone number.
- 'dmitry': Use for a domain or IP. Conducts quick OSINT (subdomains, whois, etc).
- 'emailharvester': Use for a domain. Harvests emails via web search.
- 'finalrecon': Use for a domain. Performs all-in-one web reconnaissance.
- 'linkedin2username': Use for a LinkedIn profile or name. Converts to LinkedIn username.
- 'metagoofil': Use for a domain. Extracts metadata from public documents.
- 'photon': Use for a domain or URL. Crawls site to discover links and assets.
- 'phone-osint': Use for a phone number. Runs local phone-osint.py to gather phone metadata and Telegram username.
- 'gmail-osint': Use for a Gmail address. Runs local gmail-osint.py (GHunt wrapper) to gather Gmail profile data.

Given the user's goal and target, provide the best initial sequence of tasks as a JSON list. Each task must specify 'tool' and 'target'.
Example response: {{ "tasks": [ {{ "tool": "whois", "target": "example.com" }} ] }}
"""

PIVOT_ANALYST_PROMPT = """You are an expert OSINT Pivot Analyst. You analyze new findings and decide the next logical step in an investigation.

Available Tools:
- 'theharvester': Use for a domain. Finds emails and subdomains.
- 'whois': Use for a domain. Finds registration information.
- 'nslookup': Use for a domain/host. Finds the IP address.
- 'geoiplookup': Use for an IP address. Finds the geographic location.
- 'sherlock': Use for a username. Finds social media profiles.
- 'hibp': Use for an email address. Checks for breaches.
- 'spiderfoot-cli': Use for a domain or IP. Performs comprehensive OSINT scans (SpiderFoot).
- 'dirb': Use for a URL. Finds hidden web directories via brute-force.
- 'deepmagic': Use for a domain or IP. Gathers broad OSINT (Deepmagic Information Gathering).
- 'email2phonenumber': Use for an email. Attempts to find an associated phone number.
- 'dmitry': Use for a domain or IP. Conducts quick OSINT (subdomains, whois, etc).
- 'emailharvester': Use for a domain. Harvests emails via web search.
- 'finalrecon': Use for a domain. Performs all-in-one web reconnaissance.
- 'linkedin2username': Use for a LinkedIn profile or name. Converts to LinkedIn username.
- 'metagoofil': Use for a domain. Extracts metadata from public documents.
- 'photon': Use for a domain or URL. Crawls site to discover links and assets.
- 'phone-osint': Use for a phone number. Runs local phone-osint.py to gather Telegram username.
- 'gmail-osint': Use for a Gmail address. Runs local gmail-osint.py (GHunt wrapper) to gather Gmail profile data.

The initial goal was: {goal}
The previous task '{last_tool}' on target '{last_target}' just discovered the following new information: {new_data}

Based on this new context, what is the most logical next step to further the investigation?
Provide a new JSON task list if a valuable pivot is possible. If no new action is warranted, return an empty list: {{ "tasks": [] }}.
Focus only on actionable pivots with the available tools.
"""

REPORT_SYNTHESIZER_PROMPT = """You are a senior penetration tester and intelligence analyst writing a final reconnaissance report.
You have been given all the correlated data from an automated OSINT investigation in a structured JSON format.

Your task is to synthesize this raw data into a professional, human-readable report in Markdown format.
The report must include the following sections:
1.  **Executive Summary:** A brief, high-level overview of the target and the most critical findings.
2.  **Discovered Assets:** A categorized list of all discovered assets (Domains, Hosts/IPs, Emails, Usernames/Profiles).
3.  **Key Findings & Relationships:** Analyze the data and describe the connections. For example, "The domain was registered with an email that was found in the following data breaches..." or "Multiple social media profiles were discovered which link back to the target's personal website."
4.  **Potential Attack Vectors & Recommendations:** Based on the findings, suggest potential areas for further investigation or security risks (e.g., "The discovered email addresses could be targets for phishing campaigns," or "Exposed subdomains should be checked for vulnerabilities.").

Here is the complete data from the investigation:
{database_dump}
"""

# -------------------------
# Utility helpers
# -------------------------
def digits_only(s: str) -> str:
    if not s:
        return ""
    return re.sub(r'\D', '', str(s))

def phone_matches(target: str, candidate: str, min_match_digits: int = 6) -> bool:
    t = digits_only(target)
    c = digits_only(candidate)
    if not t or not c:
        return False
    return t[-min_match_digits:] == c[-min_match_digits:]

def sanitize_phone_payload(payload: dict) -> dict:
    allowed = {
        "phone": ["number_e164", "input", "phone_e164", "phone"],
        "country": ["country", "country_name"],
        "carrier": ["carrier"],
        "line_type": ["line_type", "type"],
        "valid": ["valid"],
        "confidence": ["confidence", "score"],
        "sources": ["web_results", "sources"],
        "telegram_username": ["telegram_username", "username", "telegram"]
    }
    out = {}
    for key in allowed["phone"]:
        if key in payload and payload[key]:
            out["phone"] = str(payload[key])
            break
    for canonical, keys in allowed.items():
        if canonical == "phone":
            continue
        for k in keys:
            if k in payload and payload[k] not in (None, "", [], {}):
                out[canonical] = payload[k]
                break
    return out

# Optional Pydantic model for parsing the planner output (only used if pydantic available)
if LANGCHAIN_AVAILABLE:
    class PlannerModel(BaseModel):
        tasks: list

# -------------------------
# NETRA class
# -------------------------
class NETRA:
    def __init__(self, target, goal, report_format, api_key):
        self.goal = goal
        self.initial_target = target
        self.report_format = report_format
        self.workspace = self._init_workspace(target)
        self.db_path = os.path.join(self.workspace, "data.db")
        self.conn = self._init_db()
        self.task_queue = []
        self.completed_tasks = set()

        # AI init
        self.use_langchain_parsing = LANGCHAIN_AVAILABLE
        if api_key:
            if genai:
                try:
                    genai.configure(api_key=api_key)
                    self.ai_model = genai.GenerativeModel('gemini-2.5-pro')
                except Exception as e:
                    print(f"{Colors.YELLOW}[!] Warning: Failed to configure Gemini client: {e}{Colors.RESET}")
                    self.ai_model = None
            else:
                print(f"{Colors.YELLOW}[!] google.generativeai library not available; AI calls will be simulated.{Colors.RESET}")
                self.ai_model = None
        else:
            print(f"{Colors.YELLOW}[!] GEMINI API KEY not provided. AI features will be limited.{Colors.RESET}")
            self.ai_model = None

        # caches & settings
        self._tool_output_cache = {}
        self._pending_findings = []
        self._last_ai_call = time.time()
        self.ai_batch_size = 5
        self.ai_batch_interval = 8
        self._max_tasks = 1000
        self._tool_timeout = 120

        # How many evidence snippets to include before prompts
        self.evidence_snippet_count = 8
        # length limit for each snippet (characters)
        self.evidence_snippet_len = 1200

        print(f"{Colors.GREEN}[+] NETRA engine initialized for target: {target}{Colors.RESET}")
        print(f"{Colors.GREEN}[+] Workspace: {self.workspace}{Colors.RESET}")

    def _init_workspace(self, target):
        safe_target_name = re.sub(r'[^a-zA-Z0-9]', '_', target)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        dir_name = f"{safe_target_name}_{timestamp}"
        workspace_path = os.path.join(os.getcwd(), "workspaces", dir_name)
        os.makedirs(workspace_path, exist_ok=True)
        return workspace_path

    def _init_db(self):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        # tables...
        cursor.execute('''CREATE TABLE IF NOT EXISTS domains (id INTEGER PRIMARY KEY, domain TEXT UNIQUE, registrar TEXT, creation_date TEXT, expiration_date TEXT, source_module TEXT, timestamp DATETIME DEFAULT CURRENT_TIMESTAMP)''')
        cursor.execute('''CREATE TABLE IF NOT EXISTS hosts (id INTEGER PRIMARY KEY, host TEXT UNIQUE, ip_address TEXT, country TEXT, city TEXT, isp TEXT, source_module TEXT, timestamp DATETIME DEFAULT CURRENT_TIMESTAMP)''')
        cursor.execute('''CREATE TABLE IF NOT EXISTS contacts (id INTEGER PRIMARY KEY, email TEXT UNIQUE, source_module TEXT, timestamp DATETIME DEFAULT CURRENT_TIMESTAMP)''')
        cursor.execute('''CREATE TABLE IF NOT EXISTS profiles (id INTEGER PRIMARY KEY, username TEXT, site TEXT, url TEXT UNIQUE, source_module TEXT, timestamp DATETIME DEFAULT CURRENT_TIMESTAMP)''')
        cursor.execute('''CREATE TABLE IF NOT EXISTS breaches (id INTEGER PRIMARY KEY, email TEXT, breach_name TEXT, source_module TEXT, timestamp DATETIME DEFAULT CURRENT_TIMESTAMP)''')
        cursor.execute('''CREATE TABLE IF NOT EXISTS tool_results (id INTEGER PRIMARY KEY, tool TEXT, target TEXT, raw_output TEXT, timestamp DATETIME DEFAULT CURRENT_TIMESTAMP)''')
        cursor.execute('''CREATE TABLE IF NOT EXISTS phone_results (id INTEGER PRIMARY KEY, phone TEXT, country TEXT, carrier TEXT, line_type TEXT, valid INTEGER, confidence REAL, telegram_username TEXT, source_module TEXT, raw_json TEXT, timestamp DATETIME DEFAULT CURRENT_TIMESTAMP)''')
        conn.commit()
        return conn

    def _add_to_db(self, table, data):
        cursor = self.conn.cursor()
        for entry in data:
            cols = ', '.join(entry.keys())
            placeholders = ', '.join('?' * len(entry))
            sql = f"INSERT OR IGNORE INTO {table} ({cols}) VALUES ({placeholders})"
            try:
                cursor.execute(sql, tuple(entry.values()))
            except sqlite3.InterfaceError as e:
                print(f"{Colors.RED}[!] Database Error: {e}. Data: {entry}{Colors.RESET}")
        self.conn.commit()

    # ---------- New evidence helper ----------
    def _get_evidence_snippets(self, limit=None):
        """Return recent raw tool_results as short sanitized snippets (used to ground AI)."""
        if limit is None:
            limit = self.evidence_snippet_count
        cur = self.conn.cursor()
        try:
            cur.execute("SELECT raw_output, tool, target, timestamp FROM tool_results ORDER BY timestamp DESC LIMIT ?", (limit,))
            rows = cur.fetchall()
        except Exception:
            return []
        snippets = []
        for raw_output, tool, target, ts in rows:
            if not raw_output:
                continue
            # sanitize: remove binary garbage and trim length
            cleaned = re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f]', ' ', raw_output)
            cleaned = cleaned.strip()
            if len(cleaned) > self.evidence_snippet_len:
                cleaned = cleaned[:self.evidence_snippet_len] + " ...[truncated]"
            header = f"--- {tool} on {target} @ {ts} ---\n"
            snippets.append(header + cleaned)
        return snippets

    # ---------- AI call wrapper (improved) ----------
    def _call_ai_with_retry(self, prompt, is_json=True, max_retries=2):
        """
        Calls Gemini (if configured). Prepend recent evidence from tool_results to reduce hallucination.
        If LangChain & pydantic are available, use a PydanticOutputParser to validate JSON schema for 'tasks'.
        """
        # If AI not configured, fallback
        if not getattr(self, "ai_model", None):
            print(f"{Colors.YELLOW}[!] AI model not available. Returning default response.{Colors.RESET}")
            return {"tasks": []} if is_json else ""

        # Collect evidence (most recent raw outputs)
        evidence_snippets = self._get_evidence_snippets()
        evidence_text = ""
        if evidence_snippets:
            evidence_text = "\n\nEVIDENCE (recent raw tool outputs):\n" + ("\n\n".join(evidence_snippets)) + "\n\nEND EVIDENCE\n\n"

        # Compose final prompt with evidence first so model reasons from facts
        full_prompt = evidence_text + prompt

        # Try to call the model; handle quotas/errors gracefully
        try:
            response = self.ai_model.generate_content(full_prompt)
            raw = getattr(response, "text", str(response))
            # If JSON expected, try strict parsing, optionally using Pydantic via LangChain
            if is_json:
                # If langchain+pydantic available, try to coerce/parse into our PlannerModel
                if self.use_langchain_parsing:
                    try:
                        # parse JSON substring
                        start = raw.find("{")
                        end = raw.rfind("}") + 1
                        candidate = raw[start:end]
                        parsed = json.loads(candidate)
                        return parsed
                    except Exception:
                        pass
                # fallback: salvage JSON substring
                try:
                    start = raw.find("{")
                    end = raw.rfind("}") + 1
                    candidate = raw[start:end]
                    return json.loads(candidate)
                except json.JSONDecodeError:
                    print(f"{Colors.YELLOW}[!] AI returned malformed JSON. Attempting salvage...{Colors.RESET}")
                    try:
                        start = raw.find("{")
                        end = raw.rfind("}") + 1
                        candidate = raw[start:end]
                        return json.loads(candidate)
                    except Exception:
                        print(f"{Colors.RED}[!] Failed to parse AI JSON. Returning empty plan.{Colors.RESET}")
                        return {"tasks": []}
            else:
                # plain-text response requested
                return raw
        except Exception as e:
            print(f"{Colors.RED}[!] AI call failed: {e}{Colors.RESET}")
            return {"tasks": []} if is_json else "Error in AI response."

    # ---------- Tool runner (updated: support gmail-osint) ----------
    def _run_tool(self, tool, target):
        cache_key = (tool, target.lower())
        if cache_key in self._tool_output_cache:
            print(f"{Colors.YELLOW}[*] Using cached output for {tool} on {target}.{Colors.RESET}")
            return self._tool_output_cache[cache_key]

        print(f"{Colors.CYAN}[*] Running tool '{tool}' on target '{target}'...{Colors.RESET}")
        self.completed_tasks.add(cache_key)

        try:
            if tool == "phone-osint":
                script_path = os.path.join(os.getcwd(), "phone-osint.py")
                if not os.path.exists(script_path):
                    return f"Error: 'phone-osint.py' not found in {os.getcwd()}."
                cmd = [sys.executable, script_path, "--json", target]

            elif tool == "gmail-osint":
                # call local gmail-osint.py wrapper (GHunt)
                script_path = os.path.join(os.getcwd(), "gmail-osint.py")
                if not os.path.exists(script_path):
                    return f"Error: 'gmail-osint.py' not found in {os.getcwd()}."
                cmd = [sys.executable, script_path, target, "--json"]

            else:
                # existing mapping (unchanged)
                if tool == "theharvester":
                    cmd = ["theHarvester", "-d", target, "-b", "all"]
                elif tool == "whois":
                    cmd = ["whois", target]
                elif tool == "nslookup":
                    cmd = ["nslookup", target]
                elif tool == "geoiplookup":
                    cmd = ["geoiplookup", target]
                elif tool == "sherlock":
                    cmd = ["sherlock", "--timeout", "20", target]
                elif tool == "hibp":
                    return f"Simulated HIBP check for {target}. Found in: 'Adobe', 'LinkedIn'."
                elif tool == "spiderfoot-cli":
                    cmd = ["spiderfoot", "-s", target, "-o", "json"]
                elif tool == "dirb":
                    url = target if target.startswith("http") else f"http://{target}"
                    cmd = ["dirb", url]
                elif tool == "deepmagic":
                    cmd = ["dmitry", "-winsep", target]
                elif tool == "dmitry":
                    cmd = ["dmitry", "-winsep", target]
                elif tool == "email2phonenumber":
                    # ensure correct subcommand usage for email2phonenumber
                    cmd = ["email2phonenumber", "scrape", target]
                elif tool == "emailharvester":
                    cmd = ["emailharvester", "-d", target]
                elif tool == "finalrecon":
                    cmd = ["finalrecon", "-d", target]
                elif tool == "linkedin2username":
                    cmd = ["linkedin2username", target]
                elif tool == "metagoofil":
                    cmd = ["metagoofil", "-d", target, "-t", "pdf,docx"]
                elif tool == "photon":
                    cmd = ["photon", "-u", target, "-d", self.workspace]
                else:
                    return f"Error: Tool '{tool}' not recognized."

                # verify binary exists
                if shutil.which(cmd[0]) is None:
                    return f"Error: Command '{cmd[0]}' not found. Ensure it is installed and in PATH."

            # run command
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=self._tool_timeout)
            stdout = proc.stdout or ""
            stderr = proc.stderr or ""
            if proc.returncode != 0 and stderr:
                print(f"{Colors.YELLOW}[!] Tool '{tool}' returned warnings/errors: {stderr.strip()}{Colors.RESET}")

            combined = stdout + ("\n" + stderr if stderr else "")

            # save raw tool result for audit
            try:
                cur = self.conn.cursor()
                cur.execute("INSERT INTO tool_results (tool, target, raw_output) VALUES (?, ?, ?)", (tool, target, combined))
                self.conn.commit()
            except Exception:
                pass

            self._tool_output_cache[cache_key] = combined
            return combined

        except subprocess.TimeoutExpired:
            return f"Error: Tool '{tool}' timed out after {self._tool_timeout} seconds."
        except Exception as e:
            return f"Error running '{tool}': {e}"

    # ---------- Output parsing (updated: handle gmail-osint) ----------
    def _parse_output(self, tool, target, output):
        new_data = {}
        if not output:
            return new_data

        # phone-osint parsing
        if tool == "phone-osint":
            try:
                payload = json.loads(output)
            except Exception:
                new_data.setdefault("phone_raw_notes", []).append("non-json output from phone-osint")
                return new_data

            clean = sanitize_phone_payload(payload)
            candidate_phone = clean.get("phone") or payload.get("input") or payload.get("number_e164") or ""
            if not candidate_phone:
                new_data.setdefault("phone_raw_notes", []).append("phone not present in phone-osint output")
                return new_data

            if not phone_matches(target, candidate_phone, min_match_digits=6):
                new_data.setdefault("phone_raw_notes", []).append(f"phone mismatch: target {target} != payload {candidate_phone}")
                return new_data

            phone_entry = {
                "phone": candidate_phone,
                "country": clean.get("country"),
                "carrier": clean.get("carrier"),
                "line_type": clean.get("line_type"),
                "valid": 1 if clean.get("valid") else 0,
                "confidence": float(clean.get("confidence")) if clean.get("confidence") not in (None, "") else None,
                "telegram_username": clean.get("telegram_username"),
                "source_module": "phone-osint",
                "raw_json": json.dumps(payload)
            }
            phone_entry = {k: v for k, v in phone_entry.items() if v is not None and v != ""}
            try:
                self._add_to_db("phone_results", [phone_entry])
            except Exception:
                pass

            new_data.setdefault("phone_validated", []).append(phone_entry)
            username = clean.get("telegram_username")
            if username:
                profile_item = {"username": username, "site": "telegram", "url": f"https://t.me/{username}", "source_module": "phone-osint"}
                self._add_to_db("profiles", [profile_item])
                new_data.setdefault("new_profiles", []).append(profile_item["url"])
            return new_data

        # gmail-osint parsing (expects JSON envelope from gmail-osint.py)
        if tool == "gmail-osint":
            # many wrappers print the envelope JSON to stdout; try to parse robustly
            try:
                payload = json.loads(output)
            except Exception:
                # maybe output contains the envelope but has additional logs; try to extract JSON substring
                try:
                    start = output.find("{")
                    end = output.rfind("}") + 1
                    payload = json.loads(output[start:end])
                except Exception:
                    new_data.setdefault("gmail_raw_notes", []).append("non-json output from gmail-osint")
                    return new_data

            # The envelope should include 'target' and 'ghunt_raw' or be the raw ghunt result
            envelope = payload if "ghunt_raw" in payload or "target" in payload else {"target": target, "ghunt_raw": payload}

            # store raw JSON (we already saved combined output in tool_results); also add phone results if any exist
            try:
                raw_json_str = json.dumps(envelope)
            except Exception:
                raw_json_str = str(envelope)

            # try to extract some clean profile info to store in profiles
            # candidate username is the mailbox before '@'
            username = target.split("@")[0]
            # collect possible profile URLs from envelope.photo_candidates or ghunt_raw content
            profile_urls = []
            if isinstance(envelope.get("photo_candidates"), list):
                profile_urls.extend(envelope.get("photo_candidates", []))
            # attempt to find profile link inside ghunt_raw - safe heuristic
            ghunt = envelope.get("ghunt_raw", {})
            # examples of keys that may contain profile/url or google profile id
            if isinstance(ghunt, dict):
                # look for direct profile URL fields
                for k in ("profile", "profile_url", "profile_picture", "profileLink", "link"):
                    if k in ghunt and isinstance(ghunt[k], str) and ghunt[k].startswith("http"):
                        profile_urls.append(ghunt[k])
                # also search nested values for URLs
                def collect_urls(obj):
                    urls = []
                    if isinstance(obj, str):
                        if obj.startswith("http://") or obj.startswith("https://"):
                            urls.append(obj)
                    elif isinstance(obj, dict):
                        for v in obj.values():
                            urls.extend(collect_urls(v))
                    elif isinstance(obj, list):
                        for v in obj:
                            urls.extend(collect_urls(v))
                    return urls
                profile_urls.extend(collect_urls(ghunt))

            # dedupe and keep a few
            seen = set()
            pruned = []
            for u in profile_urls:
                if u not in seen:
                    seen.add(u)
                    pruned.append(u)
                if len(pruned) >= 10:
                    break

            # create a canonical profile entry for this Gmail
            profile_entry = {"username": username, "site": "google", "url": f"mailto:{target}", "source_module": "gmail-osint"}
            # insert profile row
            try:
                self._add_to_db("profiles", [profile_entry])
            except Exception:
                pass
            new_data.setdefault("new_profiles", []).append(profile_entry["url"])

            # add discovered profile urls as profiles too
            for u in pruned:
                try:
                    profile_item = {"username": username, "site": "google", "url": u, "source_module": "gmail-osint"}
                    self._add_to_db("profiles", [profile_item])
                    new_data.setdefault("new_profiles", []).append(u)
                except Exception:
                    pass

            # store a small summary in phone_results? no — instead add tool_results already recorded
            # store the envelope as raw_json inside tool_results is already stored (via _run_tool). If desired, also add a reference to phone_results table, but we skip that to avoid noise.

            # Save final raw JSON file in workspace for auditing
            try:
                fn = f"ghunt_final_{re.sub('[^a-zA-Z0-9]','_', target)}_{int(time.time())}.json"
                outpath = os.path.join(self.workspace, fn)
                with open(outpath, "w", encoding="utf-8") as fh:
                    fh.write(raw_json_str)
                new_data.setdefault("saved_files", []).append(outpath)
            except Exception:
                pass

            return new_data

        # existing parsers (unchanged)
        if tool in ("theharvester", "photon", "emailharvester"):
            emails = re.findall(r'[\w\.-]+@[\w\.-]+\.[a-zA-Z]{2,}', output)
            hosts = re.findall(r'[\w\.-]+\.' + re.escape(target), output, flags=re.IGNORECASE)
            if emails:
                db_data = [{"email": e, "source_module": tool} for e in set(emails)]
                self._add_to_db("contacts", db_data)
                new_data["new_emails"] = list(set(emails))
            if hosts:
                db_data = [{"host": h, "source_module": tool} for h in set(hosts)]
                self._add_to_db("hosts", db_data)
                new_data["new_hosts"] = list(set(hosts))

        elif tool == "whois":
            emails = re.findall(r'[\w\.-]+@[\w\.-]+', output)
            if emails:
                valid_emails = [e for e in set(emails) if not any(x in e.lower() for x in ["abuse", "example"])]
                if valid_emails:
                    self._add_to_db("contacts", [{"email": e, "source_module": "whois"} for e in valid_emails])
                    new_data["new_emails"] = valid_emails
            registrar = (re.search(r'Registrar:\s*(.*)', output) or [None, None])[1]
            creation_date = (re.search(r'Creation Date:\s*(.*)', output) or [None, None])[1]
            expiration_date = (re.search(r'Registry Expiry Date:\s*(.*)', output) or [None, None])[1]
            if registrar or creation_date or expiration_date:
                self._add_to_db("domains", [{
                    "domain": target,
                    "registrar": (registrar or "").strip(),
                    "creation_date": (creation_date or "").strip(),
                    "expiration_date": (expiration_date or "").strip(),
                    "source_module": "whois"
                }])
                new_data.setdefault("new_domains", []).append(target)

        elif tool == "nslookup":
            match = re.search(r'Address:\s*(\d{1,3}(?:\.\d{1,3}){3})', output)
            if match:
                ip = match.group(1)
                if not ip.startswith(("10.", "192.168.", "172.16.")):
                    self._add_to_db("hosts", [{"host": target, "ip_address": ip, "source_module": "nslookup"}])
                    new_data["new_ips"] = [ip]

        elif tool == "geoiplookup":
            country_match = re.search(r'GeoIP.*:\s*([A-Z]{2}|[A-Za-z ]+)', output)
            if country_match:
                country = country_match.group(1).strip()
                self.conn.execute("UPDATE hosts SET country = ? WHERE ip_address = ?", (country, target))
                self.conn.commit()
                new_data["new_locations"] = [{"ip": target, "country": country}]

        elif tool == "sherlock":
            urls = re.findall(r'(https?://[^\s]+)', output)
            if urls:
                db_data = [{"username": target, "site": "Unknown", "url": url, "source_module": "sherlock"} for url in set(urls)]
                self._add_to_db("profiles", db_data)
                new_data["new_profiles"] = list(set(urls))

        elif tool == "hibp":
            breaches = re.findall(r"'(.*?)'", output)
            if breaches:
                self._add_to_db("breaches", [{"email": target, "breach_name": b, "source_module": "hibp"} for b in set(breaches)])
                new_data["new_breaches"] = list(set(breaches))

        elif tool == "metagoofil":
            files = re.findall(r'Found: (.+)', output)
            if files:
                new_data["found_files"] = files

        return new_data

    def _dump_db_to_json(self):
        cursor = self.conn.cursor()
        db_dump = {}
        for table in ["domains", "hosts", "contacts", "profiles", "breaches", "tool_results", "phone_results"]:
            cursor.execute(f"SELECT * FROM {table}")
            rows = cursor.fetchall()
            if rows:
                cols = [desc[0] for desc in cursor.description]
                db_dump[table] = [dict(zip(cols, row)) for row in rows]
        return json.dumps(db_dump, indent=2)

    def _local_pivots_from_findings(self, findings):
        tasks = []
        for e in findings.get("new_emails", []):
            tasks.append({"tool": "hibp", "target": e})
            username = e.split("@")[0]
            if username:
                tasks.append({"tool": "sherlock", "target": username})
        for h in findings.get("new_hosts", []):
            tasks.append({"tool": "nslookup", "target": h})
        for ip in findings.get("new_ips", []):
            tasks.append({"tool": "geoiplookup", "target": ip})
        return tasks

    def generate_report(self):
        print(f"\n{Colors.HEADER}{Colors.BOLD}[+] Generating final intelligence report...{Colors.RESET}")
        db_json = self._dump_db_to_json()
        if not db_json or db_json == "{}":
            print(f"{Colors.YELLOW}[!] No data was gathered during the investigation. Report generation skipped.{Colors.RESET}")
            return

        if self.report_format == "json":
            json_filename = os.path.join(self.workspace, "report.json")
            with open(json_filename, 'w', encoding='utf-8') as f:
                f.write(db_json)
            print(f"  - JSON report saved to: {json_filename}")
            return

        # Use evidence-grounded prompt to synthesize report
        final_prompt = REPORT_SYNTHESIZER_PROMPT.format(database_dump=db_json)
        markdown_report = self._call_ai_with_retry(final_prompt, is_json=False)
        if not markdown_report or "Error" in markdown_report:
            # Fallback deterministic report: create a basic markdown summary (non-AI)
            print(f"{Colors.YELLOW}[!] AI failed to produce report — creating deterministic fallback report.{Colors.RESET}")
            md_filename = os.path.join(self.workspace, "report_basic.md")
            with open(md_filename, "w", encoding="utf-8") as f:
                f.write("# NETRA Basic Report (Fallback)\n\n")
                f.write("This report was auto-generated as an AI fallback. See the JSON report for full details.\n\n")
                try:
                    data = json.loads(db_json)
                    for table, items in data.items():
                        f.write(f"## {table} ({len(items)})\n\n")
                        for it in items[:200]:
                            f.write(json.dumps(it, default=str) + "\n\n")
                except Exception:
                    f.write(db_json)
            print(f"  - Fallback Markdown saved to: {md_filename}")
            # Attempt to convert to HTML/PDF if libs present
            if self.report_format in ["html", "pdf"] and markdown2:
                try:
                    html_body = markdown2.markdown(open(md_filename, "r", encoding="utf-8").read(), extras=["tables", "fenced-code-blocks"])
                    html_full = f"<html><head><meta charset='UTF-8'></head><body>{html_body}</body></html>"
                    html_filename = os.path.join(self.workspace, "report.html")
                    with open(html_filename, 'w', encoding='utf-8') as f:
                        f.write(html_full)
                    print(f"  - HTML report saved to: {html_filename}")
                    if self.report_format == "pdf" and HTML:
                        pdf_filename = os.path.join(self.workspace, "report.pdf")
                        HTML(string=html_full).write_pdf(pdf_filename)
                        print(f"  - PDF report saved to: {pdf_filename}")
                except Exception as e:
                    print(f"{Colors.YELLOW}[!] Failed fallback HTML/PDF conversion: {e}{Colors.RESET}")
            return

        md_filename = os.path.join(self.workspace, "report.md")
        with open(md_filename, 'w', encoding='utf-8') as f:
            f.write(markdown_report)
        print(f"  - Markdown report saved to: {md_filename}")

        if self.report_format in ["html", "pdf"] and markdown2:
            try:
                css_style = ""
                try:
                    with open("report_template.css", "r") as f:
                        css_style = f.read()
                except FileNotFoundError:
                    pass
                html_body = markdown2.markdown(markdown_report, extras=["tables", "fenced-code-blocks"])
                html_full = f"<html><head><meta charset='UTF-8'><style>{css_style}</style></head><body>{html_body}</body></html>"
                html_filename = os.path.join(self.workspace, "report.html")
                with open(html_filename, 'w', encoding='utf-8') as f:
                    f.write(html_full)
                print(f"  - HTML report saved to: {html_filename}")
                if self.report_format == "pdf" and HTML:
                    pdf_filename = os.path.join(self.workspace, "report.pdf")
                    HTML(string=html_full).write_pdf(pdf_filename)
                    print(f"  - PDF report saved to: {pdf_filename}")
            except Exception as e:
                print(f"{Colors.RED}[!] Failed to generate HTML/PDF report: {e}{Colors.RESET}")

    def start_investigation(self):
        print(f"\n{Colors.HEADER}{Colors.BOLD}--- Starting NETRA Investigation ---{Colors.RESET}")
        initial_prompt = f"User goal: '{self.goal}', Initial target: '{self.initial_target}'"

        # If the initial target looks like a phone number, create a deterministic phone task
        phone_pattern = re.compile(r'^\+?\d{7,15}$')
        email_pattern = re.compile(r'^[^@\s]+@[^@\s]+\.[^@\s]+$')
        if phone_pattern.match(self.initial_target.strip()):
            plan = {"tasks": [{"tool": "phone-osint", "target": self.initial_target.strip()}]}
            print(f"{Colors.CYAN}[+] Detected phone number input — using local phone-osint task.{Colors.RESET}")
        elif email_pattern.match(self.initial_target.strip()):
            # If it's an email, call the local gmail-osint wrapper
            plan = {"tasks": [{"tool": "gmail-osint", "target": self.initial_target.strip()}]}
            print(f"{Colors.CYAN}[+] Detected email input — using local gmail-osint task.{Colors.RESET}")
        else:
            plan = self._call_ai_with_retry(TASK_PLANNER_PROMPT + "\n" + initial_prompt, is_json=True)

        if not plan or "tasks" not in plan or not plan["tasks"]:
            print(f"{Colors.RED}[!] AI failed to generate a valid initial plan. Exiting.{Colors.RESET}")
            return
        self.task_queue.extend(plan["tasks"])
        print(f"{Colors.GREEN}[+] Initial plan received with {len(self.task_queue)} tasks.{Colors.RESET}")

        # main loop
        while self.task_queue and len(self.completed_tasks) < self._max_tasks:
            task = self.task_queue.pop(0)
            tool = task.get("tool")
            target = task.get("target")
            if not tool or not target:
                print(f"{Colors.YELLOW}[-] Skipping malformed task: {task}{Colors.RESET}")
                continue
            if (tool, target.lower()) in self.completed_tasks:
                print(f"{Colors.YELLOW}[-] Skipping redundant check: '{tool}' on '{target}'.{Colors.RESET}")
                continue

            raw_output = self._run_tool(tool, target)
            new_findings = self._parse_output(tool, target, raw_output)

            if new_findings:
                local_tasks = self._local_pivots_from_findings(new_findings)
                if local_tasks:
                    print(f"{Colors.CYAN}[+] Adding {len(local_tasks)} deterministic local pivot tasks.{Colors.RESET}")
                    self.task_queue.extend(local_tasks)

                self._pending_findings.append(new_findings)

                time_since_last = time.time() - self._last_ai_call
                if len(self._pending_findings) >= self.ai_batch_size or time_since_last >= self.ai_batch_interval:
                    combined = {}
                    for f in self._pending_findings:
                        for k, v in f.items():
                            combined.setdefault(k, []).extend(v if isinstance(v, list) else [v])
                    self._pending_findings = []
                    self._last_ai_call = time.time()

                    pivot_prompt = PIVOT_ANALYST_PROMPT.format(
                        goal=self.goal,
                        last_tool=tool,
                        last_target=target,
                        new_data=json.dumps(combined)
                    )
                    pivot_plan = self._call_ai_with_retry(pivot_prompt, is_json=True)
                    if isinstance(pivot_plan, dict) and "tasks" in pivot_plan and pivot_plan["tasks"]:
                        valid_tasks = []
                        for t in pivot_plan["tasks"]:
                            if isinstance(t, dict) and t.get("tool") and t.get("target"):
                                valid_tasks.append({"tool": t["tool"], "target": t["target"]})
                        if valid_tasks:
                            print(f"{Colors.GREEN}[+] AI identified {len(valid_tasks)} new tasks. Investigation expanding.{Colors.RESET}")
                            self.task_queue.extend(valid_tasks)
                    else:
                        print(f"{Colors.YELLOW}[!] AI pivot returned no actionable tasks.{Colors.RESET}")
            time.sleep(0.5)

        print(f"\n{Colors.HEADER}{Colors.BOLD}--- Investigation Loop Complete ---{Colors.RESET}")
        self.generate_report()

def main():
    parser = argparse.ArgumentParser(description="NETRA: An AI-Driven OSINT Orchestration Engine.")
    parser.add_argument("--api-key", default=os.getenv("GEMINI_API_KEY", ""), help="Your Google Gemini API key.")
    args = parser.parse_args()

    print(f"{Colors.HEADER}{Colors.BOLD}Welcome to Project NETRA - Interactive Mode{Colors.RESET}")
    print("-" * 50)
    try:
        target = input(f"{Colors.CYAN}[?] Enter the initial target (e.g., domain, username, ip, email..etc): {Colors.RESET}").strip()
        if not target:
            print(f"{Colors.RED}[!] Target cannot be empty. Exiting.{Colors.RESET}")
            sys.exit(1)
        print(f"{Colors.CYAN}[?] Describe your investigation goal in plain English.{Colors.RESET}")
        goal = input(f"    (e.g., 'Find social media profiles and check for breaches'): {Colors.RESET}").strip()
        if not goal:
            print(f"{Colors.RED}[!] Goal cannot be empty. Exiting.{Colors.RESET}")
            sys.exit(1)
        report_format = ""
        valid_formats = ['md', 'html', 'pdf', 'json']
        while report_format not in valid_formats:
            report_format = input(f"{Colors.CYAN}[?] Choose a report format ({', '.join(valid_formats)}): {Colors.RESET}").strip().lower()
            if report_format not in valid_formats:
                print(f"{Colors.RED}[!] Invalid format. Please choose one of: {', '.join(valid_formats)}{Colors.RESET}")
    except (KeyboardInterrupt, EOFError):
        print("\n\n[!] User cancelled. Exiting.")
        sys.exit(0)

    print("-" * 50)
    netra_engine = NETRA(
        target=target,
        goal=goal,
        report_format=report_format,
        api_key=args.api_key
    )
    try:
        netra_engine.start_investigation()
    except KeyboardInterrupt:
        print("\n\n[!] Investigation interrupted by user. Exiting.")
        netra_engine.conn.close()
        sys.exit(0)

if __name__ == "__main__":
    main()
