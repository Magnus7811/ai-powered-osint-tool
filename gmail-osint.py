#!/usr/bin/env python3
"""
gmail-osint.py - Simple GHunt wrapper for NETRA (improved URL extraction)

This wrapper:
 - Runs GHunt CLI: `ghunt email <email> --json <outfile>`
 - Loads GHunt JSON (from file or stdout)
 - Extracts URLs robustly (regex anywhere in strings)
 - Produces a normalized envelope with:
     - ghunt_raw, ghunt_raw_file, extracted_urls_count
     - photo_candidates, maps_links, profile_links
 - Optionally downloads candidate photos
 - Writes a final envelope JSON file (ghunt_final_*.json)
 - Prints the envelope when called with --json (NETRA-friendly)

Usage:
  python3 gmail-osint.py target@gmail.com --json
  python3 gmail-osint.py target@gmail.com --json --download-photos
"""

from __future__ import annotations
import argparse
import json
import os
import shutil
import subprocess
import sys
import time
import re
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional
import urllib.request
import urllib.parse

# ---------------- helpers ----------------
def find_executable(name: str) -> Optional[str]:
    return shutil.which(name)

def safe_filename(s: str) -> str:
    return "".join(c if c.isalnum() or c in "._-@" else "_" for c in s)

def dump_json(path: Path, obj: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(obj, fh, indent=2, ensure_ascii=False)

def load_json(path: Path) -> Any:
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)

URL_RE = re.compile(r"https?://[^\s\"'<>]+", re.IGNORECASE)

def recursive_collect_urls(obj: Any) -> List[str]:
    """
    Walk nested structures and extract any http/https URLs found anywhere inside strings.
    Returns deduped list preserving first-seen order.
    """
    urls: List[str] = []

    def walk(x: Any):
        if x is None:
            return
        if isinstance(x, str):
            for m in URL_RE.findall(x):
                urls.append(m)
        elif isinstance(x, dict):
            for v in x.values():
                walk(v)
        elif isinstance(x, (list, tuple)):
            for v in x:
                walk(v)
        else:
            # try stringifying other types
            try:
                s = str(x)
            except Exception:
                s = ""
            if s:
                for m in URL_RE.findall(s):
                    urls.append(m)

    walk(obj)

    # dedupe preserving first-seen order, normalize trivial trailing punctuation
    seen = set()
    out = []
    for u in urls:
        u_clean = u.rstrip('.,;:)]}\'"')
        if u_clean not in seen:
            seen.add(u_clean)
            out.append(u_clean)
    return out

def download_url(url: str, outdir: Path, timeout: int = 20) -> Optional[str]:
    try:
        parsed = urllib.parse.urlsplit(url)
        filename = os.path.basename(parsed.path) or urllib.parse.quote_plus(url)[:40]
        safe_name = safe_filename(filename)
        outpath = outdir / safe_name
        req = urllib.request.Request(url, headers={"User-Agent": "gmail-osint/1.0"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            with open(outpath, "wb") as fh:
                fh.write(resp.read())
        return str(outpath)
    except Exception:
        return None

# ---------------- main ----------------
def main() -> None:
    p = argparse.ArgumentParser(description="Run GHunt email module and output normalized JSON for NETRA.")
    p.add_argument("target", help="Gmail address to investigate (e.g., user@gmail.com).")
    p.add_argument("--out", help="Desired GHunt raw JSON output file (ghunt will write here). If omitted, a timestamped file in cwd is used.")
    p.add_argument("--json", action="store_true", help="Print normalized JSON envelope to stdout (NETRA-friendly).")
    p.add_argument("--token", help="Optional GHunt master token (best-effort).")
    p.add_argument("--download-photos", action="store_true", help="Attempt to download candidate photo URLs (public).")
    p.add_argument("--timeout", type=int, default=180, help="GHunt CLI timeout seconds (default 180).")
    args = p.parse_args()

    target = args.target.strip()
    if "@" not in target:
        err = {"error": "invalid_target", "message": "target must be an email address"}
        print(json.dumps(err))
        sys.exit(2)

    ghunt_bin = find_executable("ghunt")
    if not ghunt_bin:
        err = {"error": "ghunt_not_found", "message": "ghunt CLI not found in PATH. Install via 'pipx install ghunt' or 'pip install ghunt'."}
        print(json.dumps(err))
        sys.exit(2)

    timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    safe_target = safe_filename(target)
    default_raw = Path.cwd() / f"ghunt_{safe_target}_{timestamp}.json"
    raw_out = Path(args.out) if args.out else default_raw

    cmd = [ghunt_bin, "email", target, "--json", str(raw_out)]
    env = os.environ.copy()
    if args.token:
        env["GHUNT_MASTER_TOKEN"] = args.token
        env["GHUNT_TOKEN"] = args.token

    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, env=env, timeout=args.timeout)
    except subprocess.TimeoutExpired:
        print(json.dumps({"error": "ghunt_timeout", "message": "ghunt CLI timed out"}))
        sys.exit(1)
    except Exception as e:
        print(json.dumps({"error": "ghunt_error", "message": str(e)}))
        sys.exit(1)

    stdout = proc.stdout or ""
    stderr = proc.stderr or ""
    if proc.returncode != 0:
        # GHunt may still have created a file; only bail if nothing useful
        if not raw_out.exists():
            print(json.dumps({"error": "ghunt_failed", "returncode": proc.returncode, "stdout": stdout.strip(), "stderr": stderr.strip()}))
            sys.exit(1)
        # else continue to attempt reading file

    # Try to load the written JSON. If GHunt wrote to stdout instead, try parsing stdout.
    ghunt_raw = None
    if raw_out.exists():
        try:
            ghunt_raw = load_json(raw_out)
        except Exception as e:
            # try to salvage by parsing stdout if present
            try:
                ghunt_raw = json.loads(stdout) if stdout else None
            except Exception:
                print(json.dumps({"error": "ghunt_parse_failed", "message": "Failed to parse ghunt json file", "exception": str(e)}))
                sys.exit(1)
    else:
        # try parse stdout as JSON
        try:
            ghunt_raw = json.loads(stdout)
            # write to raw_out for record
            try:
                dump_json(raw_out, ghunt_raw)
            except Exception:
                pass
        except Exception:
            print(json.dumps({"error": "no_ghunt_output", "message": "ghunt did not produce expected JSON file and stdout is not JSON", "stdout": stdout, "stderr": stderr}))
            sys.exit(1)

    # Build normalized envelope
    envelope: Dict[str, Any] = {
        "target": target,
        "timestamp": time.time(),
        "ghunt_raw_file": str(raw_out.resolve()) if raw_out.exists() else None,
        "ghunt_raw": ghunt_raw,
    }

    # collect urls robustly and classify them
    urls = recursive_collect_urls(ghunt_raw)
    envelope["extracted_urls_count"] = len(urls)

    # Photo candidates: common Google image hosts and direct image extensions
    photo_candidates = []
    for u in urls:
        low = u.lower()
        if any(d in low for d in ("googleusercontent.com", "lh3.googleusercontent.com", "photos.google.com", "gstatic.com", "googleapis.com")):
            photo_candidates.append(u)
        elif re.search(r'\.(jpg|jpeg|png|gif|webp)(?:$|\?)', low):
            photo_candidates.append(u)
    envelope["photo_candidates_count"] = len(photo_candidates)
    envelope["photo_candidates"] = photo_candidates

    # Maps links (google maps / maps.app.goo.gl)
    maps_links = [u for u in urls if "google.com/maps" in u or "maps.app.goo.gl" in u or "google.com/maps/contrib" in u]
    envelope["maps_links"] = maps_links

    # Profile links: heuristic (About Me, Google+ legacy, People, Maps contributor pages)
    profile_patterns = ("aboutme.google.com", "plus.google.com", "people.google.com", "google.com/maps/contrib", "profiles.google.com")
    profile_links = [u for u in urls if any(p in u.lower() for p in profile_patterns)]
    # include some other likely social/profile URLs (from ghunt output)
    # also include the homepage/profile-like URLs found
    envelope["profile_links"] = profile_links

    # Optionally download photos
    downloaded = []
    if args.download_photos and photo_candidates:
        photos_dir = Path.cwd() / f"ghunt_photos_{safe_target}_{timestamp}"
        photos_dir.mkdir(parents=True, exist_ok=True)
        for u in photo_candidates:
            p = download_url(u, photos_dir)
            if p:
                downloaded.append(p)
        envelope["downloaded_photos"] = downloaded
        envelope["photos_dir"] = str(photos_dir.resolve())

    # final normalized file for NETRA to ingest
    final_path = raw_out.parent / f"ghunt_final_{safe_target}_{timestamp}.json"
    try:
        dump_json(final_path, envelope)
        envelope["ghunt_final_file"] = str(final_path.resolve())
    except Exception:
        envelope["ghunt_final_file"] = None

    # Output: print envelope JSON if requested (NETRA expects JSON)
    if args.json:
        print(json.dumps(envelope, indent=2, ensure_ascii=False))
    else:
        outinfo = {
            "ghunt_raw_file": envelope.get("ghunt_raw_file"),
            "ghunt_final_file": envelope.get("ghunt_final_file"),
            "extracted_urls": envelope.get("extracted_urls_count"),
            "photo_candidates": envelope.get("photo_candidates_count"),
            "maps_links": len(envelope.get("maps_links", [])),
            "downloaded_photos": len(downloaded),
        }
        print(json.dumps(outinfo))
    sys.exit(0)

if __name__ == "__main__":
    main()
