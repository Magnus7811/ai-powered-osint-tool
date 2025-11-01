#!/usr/bin/env python3
"""
phone_api_osint.py - Phone OSINT using APIs and Web Scraping

Features:
 - Normalize phone numbers (E.164 via phonenumbers)
 - Numverify API enrichment (requires API key)
 - AbstractAPI enrichment (requires API key)
 - IPQualityScore API enrichment (requires API key)
 - Twilio Lookup API enrichment (requires Account SID & Auth Token)
 - Web search (googlesearch) to find pages mentioning the number
 - Fetch & scrape top pages for context snippets
 - Output structured JSON
"""

import argparse
import json
import re
import sys
import time
import os
from typing import List, Dict, Any, Optional

# --- Import Core Libraries ---
try:
    # Need to import the top-level module first
    import phonenumbers
    # Then import submodules
    import phonenumbers.geocoder
    try:
        import phonenumbers.carrier
        carrier_available = True
    except ImportError:
        carrier_available = False
    import requests
    from bs4 import BeautifulSoup
except ImportError as e:
    print(f"[!] Error: Missing core library: {e}. Please install requirements.")
    sys.exit(1)

# --- Import Optional Libraries ---
# Twilio
try:
    from twilio.rest import Client
    from twilio.base.exceptions import TwilioRestException
    twilio_available = True
except ImportError:
    twilio_available = False
    # Don't exit, just warn if Twilio args are used later

# googlesearch
try:
    from googlesearch import search as google_search
except ImportError:
    google_search = None
    # Don't exit, just warn if web search is attempted

# lxml
try:
    import lxml
    BS_PARSER = "lxml"
except ImportError:
    BS_PARSER = "html.parser"

# --- Helpers: normalization ---
def normalize_number(raw: str, default_region: Optional[str] = None) -> Optional[str]:
    """Normalizes a phone number to E.164 format."""
    try:
        parsed = phonenumbers.parse(raw, default_region)
        if phonenumbers.is_possible_number(parsed) or phonenumbers.is_valid_number(parsed):
            return phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.E164)
        return None
    except phonenumbers.NumberParseException:
        digits = re.sub(r'\D+', '', raw)
        if default_region:
            try:
                parsed = phonenumbers.parse(digits, default_region)
                if phonenumbers.is_possible_number(parsed) or phonenumbers.is_valid_number(parsed):
                    return phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.E164)
            except phonenumbers.NumberParseException:
                pass
        return None

# --- API Adapters ---
def numverify_lookup(num: str, api_key: str, timeout: int = 15) -> Optional[Dict[str, Any]]:
    """Queries the Numverify API."""
    if not api_key: return {"status": "skipped", "reason": "API key not provided"}
    try:
        url = "http://apilayer.net/api/validate"
        params = {"access_key": api_key, "number": num}
        r = requests.get(url, params=params, timeout=timeout)
        r.raise_for_status()
        return r.json()
    except requests.exceptions.RequestException as e:
        return {"error": f"Request failed: {e}", "status_code": getattr(e.response, 'status_code', None)}
    except Exception as e:
        return {"error": f"An unexpected error occurred: {e}"}

def abstract_lookup(num: str, api_key: str, timeout: int = 15) -> Optional[Dict[str, Any]]:
    """Queries the AbstractAPI Phone Validation API."""
    if not api_key: return {"status": "skipped", "reason": "API key not provided"}
    try:
        url = "https://phonevalidation.abstractapi.com/v1/"
        params = {"api_key": api_key, "phone": num}
        r = requests.get(url, params=params, timeout=timeout)
        r.raise_for_status()
        return r.json()
    except requests.exceptions.RequestException as e:
        return {"error": f"Request failed: {e}", "status_code": getattr(e.response, 'status_code', None)}
    except Exception as e:
        return {"error": f"An unexpected error occurred: {e}"}

def ipqs_lookup(num: str, api_key: str, timeout: int = 15) -> Optional[Dict[str, Any]]:
    """Queries the IPQualityScore Phone Number Reputation API."""
    if not api_key: return {"status": "skipped", "reason": "API key not provided"}
    try:
        num_no_plus = num.lstrip('+')
        url = f"https://ipqualityscore.com/api/json/phone/{api_key}/{num_no_plus}"
        r = requests.get(url, timeout=timeout)
        r.raise_for_status()
        return r.json()
    except requests.exceptions.RequestException as e:
        return {"error": f"Request failed: {e}", "status_code": getattr(e.response, 'status_code', None)}
    except Exception as e:
        return {"error": f"An unexpected error occurred: {e}"}

def twilio_lookup(num: str, account_sid: str, auth_token: str, timeout: int = 15) -> Optional[Dict[str, Any]]:
    """Queries the Twilio Lookup V2 API."""
    if not account_sid or not auth_token:
        return {"status": "skipped", "reason": "Account SID or Auth Token not provided"}
    if not twilio_available:
        return {"status": "skipped", "reason": "Twilio library not installed"}

    try:
        client = Client(account_sid, auth_token)
        # Use a timeout for the client request if possible (check Twilio library docs, may need configuration)
        phone_number = client.lookups.v2 \
                             .phone_numbers(num) \
                             .fetch(fields='line_type_intelligence,caller_name') # Adjust fields as needed

        result = {
            "valid": phone_number.valid,
            "country_code": phone_number.country_code,
            "national_format": phone_number.national_format,
            # Safely access potentially nested attributes
            "line_type_intelligence": {
                "carrier_name": getattr(getattr(phone_number, 'line_type_intelligence', {}), 'carrier_name', None),
                "type": getattr(getattr(phone_number, 'line_type_intelligence', {}), 'type', None),
            } if getattr(phone_number, 'line_type_intelligence', None) else None,
             "caller_name": {
                "caller_name": getattr(getattr(phone_number, 'caller_name', {}), 'caller_name', None),
                "caller_type": getattr(getattr(phone_number, 'caller_name', {}), 'caller_type', None),
             } if getattr(phone_number, 'caller_name', None) else None,
        }
        return result
    except TwilioRestException as e:
        return {"error": f"Twilio API Error: {e.status} - {e.msg}", "status_code": e.status}
    except Exception as e:
        return {"error": f"An unexpected error occurred with Twilio: {e}"}


# --- Web search + fetch snippets ---
def web_search_hits(query: str, top_n: int = 10, pause: float = 2.0) -> List[str]:
    """Performs a Google search and returns the top N results."""
    if not google_search:
        print("[!] Web search skipped: googlesearch-python library not installed.")
        return []
    try:
        print(f"[*] Performing web search for '{query}'...")
        search_query = f'"{query}"'
        # FIX: Use 'num_results' instead of 'num'
        results = list(google_search(query=search_query, num_results=top_n, stop=top_n, pause=pause))
        print(f"[*] Found {len(results)} potential web results.")
        return results
    except Exception as e:
        print(f"[!] Web search failed: {e}")
        return []

def fetch_snippets(urls: List[str], phone_raw: str, phone_norm: str, timeout: int = 10, max_snippets_per_url: int = 3) -> List[Dict[str, Any]]:
    """Fetches web pages and extracts text snippets containing the phone number."""
    if not urls: return []
    print(f"[*] Fetching up to {len(urls)} pages for context snippets...")
    session = requests.Session()
    headers = { "User-Agent": "Mozilla/5.0 (compatible; NetraOSINTBot/1.0; +https://github.com/yourrepo)"}
    snippets_found = []
    raw_digits = re.sub(r'\D+', '', phone_raw)
    norm_digits = re.sub(r'\D+', '', phone_norm)
    patterns = [re.escape(phone_raw), re.escape(phone_norm)]
    if raw_digits != norm_digits: patterns.append(raw_digits)
    context_patterns_str = [f'\\b{p}\\b' for p in patterns]
    context_pattern = re.compile(f'.{{0,60}}(?:{"|".join(context_patterns_str)}).{{0,60}}', re.IGNORECASE | re.DOTALL)

    for i, u in enumerate(urls):
        print(f"  - Fetching page {i+1}/{len(urls)}: {u[:80]}...")
        try:
            r = session.get(u, headers=headers, timeout=timeout, allow_redirects=True)
            r.raise_for_status()
            content_type = r.headers.get('Content-Type', '').lower()
            if not ('html' in content_type or 'text' in content_type):
                 print(f"    - Skipping non-text content: {content_type}")
                 continue
            soup = BeautifulSoup(r.content, BS_PARSER)
            page_text = soup.get_text(separator="\n", strip=True)
            found_snippets_for_url = []
            matches = context_pattern.finditer(page_text)
            for match in matches:
                snippet = match.group(0).strip().replace('\n', ' ').replace('\r', '')
                if snippet:
                    found_snippets_for_url.append(snippet)
                    if len(found_snippets_for_url) >= max_snippets_per_url: break
            if found_snippets_for_url:
                print(f"    + Found {len(found_snippets_for_url)} snippet(s).")
                snippets_found.append({"url": u, "status": r.status_code, "snippets": found_snippets_for_url})
        except requests.exceptions.RequestException as e: print(f"    - Failed to fetch {u}: {e}")
        except Exception as e: print(f"    - Error processing {u}: {e}")
        time.sleep(1.0) # Be polite

    print(f"[*] Finished fetching pages. Found snippets on {len(snippets_found)} pages.")
    return snippets_found

# --- Main Logic ---
def main():
    p = argparse.ArgumentParser(description="Phone Number OSINT via APIs and Web Scraping")
    p.add_argument("number", help="Phone number (international format preferred, e.g., +1...).")
    p.add_argument("--default-region", help="Default region for parsing if country code is missing (e.g., US, GB).", default=None)
    # API Keys
    p.add_argument("--numverify-key", help="Numverify API key.", default=os.environ.get("NUMVERIFY_API_KEY"))
    p.add_argument("--abstract-key", help="AbstractAPI Phone Validation key.", default=os.environ.get("ABSTRACT_API_KEY"))
    p.add_argument("--ipqs-key", help="IPQualityScore API key.", default=os.environ.get("IPQS_API_KEY"))
    p.add_argument("--twilio-sid", help="Twilio Account SID.", default=os.environ.get("TWILIO_ACCOUNT_SID"))
    p.add_argument("--twilio-token", help="Twilio Auth Token.", default=os.environ.get("TWILIO_AUTH_TOKEN"))
    # Other options
    p.add_argument("--max-results", help="Max web search results (default 5).", type=int, default=5)
    p.add_argument("--max-pages", help="Max pages to fetch for context (default 3).", type=int, default=3)
    p.add_argument("--json", help="Print machine-readable JSON only.", action="store_true")
    p.add_argument("--no-web", help="Skip web search & scraping.", action="store_true")
    p.add_argument("--timeout", help="Timeout in seconds for API/web requests (default 15).", type=int, default=15)
    args = p.parse_args()

    # --- 1. Normalize Input ---
    raw_in = args.number
    print(f"[*] Normalizing '{raw_in}'...")
    normalized = normalize_number(raw_in, args.default_region)

    result: Dict[str, Any] = {
        "input": raw_in,
        "number_e164": normalized,
        "normalized_ok": bool(normalized),
        "basic_info": {},
        "api_results": {
             "numverify": None, "abstract": None, "ipqs": None, "twilio": None,
        },
        "web_results": [], "web_snippets": [],
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    }

    if not normalized:
        result["error"] = "Could not normalize the provided phone number."
        print(json.dumps(result, indent=2))
        sys.exit(1)

    print(f"[*] Normalized to: {normalized}")

    # --- 2. Get Basic Info via phonenumbers ---
    # FIX: Ensure phonenumbers module is directly accessed
    basic_info = {}
    try:
        # Use the imported phonenumbers module directly
        parsed_num = phonenumbers.parse(normalized, None)
        basic_info["country_code"] = phonenumbers.region_code_for_number(parsed_num)
        basic_info["location"] = phonenumbers.geocoder.description_for_number(parsed_num, "en")

        if carrier_available:
            try:
                # Access carrier submodule via the main phonenumbers module
                carrier_name = phonenumbers.carrier.name_for_number(parsed_num, "en")
                if carrier_name: basic_info["carrier"] = carrier_name
            except Exception as carrier_exc:
                basic_info["carrier_error"] = str(carrier_exc)
        else:
             basic_info["carrier_info"] = "Not available (phonenumbers[carrier] extra not installed?)"


        basic_info["is_valid"] = phonenumbers.is_valid_number(parsed_num)
        basic_info["is_possible"] = phonenumbers.is_possible_number(parsed_num)

    except Exception as e:
        print(f"[!] Error getting basic info: {e}")
        basic_info["error"] = str(e)

    result["basic_info"] = basic_info


    # --- 3. Query APIs ---
    print("[*] Querying enrichment APIs (if keys/creds are provided)...")
    result["api_results"]["numverify"] = numverify_lookup(normalized, args.numverify_key, args.timeout)
    result["api_results"]["abstract"] = abstract_lookup(normalized, args.abstract_key, args.timeout)
    result["api_results"]["ipqs"] = ipqs_lookup(normalized, args.ipqs_key, args.timeout)
    result["api_results"]["twilio"] = twilio_lookup(normalized, args.twilio_sid, args.twilio_token, args.timeout)


    # --- 4. Web Search & Snippets ---
    web_hits_urls = []
    if not args.no_web:
        web_hits_urls = web_search_hits(normalized, top_n=args.max_results)
        urls_to_fetch = web_hits_urls[: args.max_pages]
        snippets = fetch_snippets(urls_to_fetch, raw_in, normalized, timeout=args.timeout)
        result["web_results"] = web_hits_urls
        result["web_snippets"] = snippets
    else:
        print("[*] Web search skipped as requested.")

    # --- 5. Final Output ---
    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print("\n--- NETRA Phone OSINT Report ---")
        print(f"Input:           {result['input']}")
        print(f"Normalized (E164): {result['number_e164']}")
        print("\nBasic Info (from phonenumbers):")
        for key, value in result['basic_info'].items():
            print(f"  {key.replace('_', ' ').title()}: {value}")

        print("\nAPI Enrichment Results:")
        for api_name, api_res in result['api_results'].items():
            if api_res:
                 print(f"  {api_name.title()}:")
                 if isinstance(api_res, dict) and "error" in api_res:
                     print(f"    Status: Error ({api_res.get('status_code', 'N/A')}) - {api_res['error']}")
                 elif isinstance(api_res, dict) and api_res.get("status") == "skipped":
                     print(f"    Status: Skipped ({api_res.get('reason', '')})")
                 else:
                     details = {}
                     if api_name == 'numverify':
                         details['Valid'] = api_res.get('valid')
                         details['Country'] = api_res.get('country_name')
                         details['Location'] = api_res.get('location')
                         details['Carrier'] = api_res.get('carrier')
                         details['Line Type'] = api_res.get('line_type')
                     elif api_name == 'abstract':
                         details['Valid'] = api_res.get('valid')
                         details['Country'] = api_res.get('country', {}).get('name')
                         details['Location'] = api_res.get('location')
                         details['Carrier'] = api_res.get('carrier')
                         details['Line Type'] = api_res.get('type')
                     elif api_name == 'ipqs':
                         details['Valid'] = api_res.get('valid')
                         details['Recent Abuse'] = api_res.get('recent_abuse')
                         details['Fraud Score'] = api_res.get('fraud_score')
                         details['VOIP'] = api_res.get('voip')
                         details['Risky'] = api_res.get('risky')
                         details['Carrier'] = api_res.get('carrier')
                         details['Line Type'] = api_res.get('line_type')
                     elif api_name == 'twilio':
                         details['Valid'] = api_res.get('valid')
                         details['Country'] = api_res.get('country_code')
                         details['National Format'] = api_res.get('national_format')
                         lti = api_res.get('line_type_intelligence')
                         if lti:
                             details['Carrier (Twilio)'] = lti.get('carrier_name')
                             details['Line Type (Twilio)'] = lti.get('type')
                         cn = api_res.get('caller_name')
                         if cn:
                             details['Caller Name (Twilio)'] = cn.get('caller_name')
                             details['Caller Type (Twilio)'] = cn.get('caller_type')

                     printed_details = False
                     for k, v in details.items():
                         if v is not None:
                             print(f"    {k}: {v}")
                             printed_details = True
                     if not printed_details and isinstance(api_res, dict): # Check if it's not an error/skipped dict
                         print("    No specific details extracted from successful response.")
            else:
                 print(f"  {api_name.title()}: Skipped (No API key/creds or error during lookup)")


        if not args.no_web:
            print("\nWeb Search Results (Top URLs):")
            if result['web_results']:
                for i, url in enumerate(result['web_results']): print(f"  {i+1}. {url}")
            else: print("  No results found or web search skipped.")

            print("\nWeb Snippets (Context from Pages):")
            if result['web_snippets']:
                 for item in result['web_snippets']:
                     print(f"  URL: {item['url']}")
                     for snippet in item['snippets']: print(f"    -> ...{snippet}...")
                     print("")
            else: print("  No snippets found or web search skipped.")

        print("-" * 30)

if __name__ == "__main__":
    # Dependency Check (Moved imports to top for clarity and early failure)
    main()

