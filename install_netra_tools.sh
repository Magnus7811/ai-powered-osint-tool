#!/usr/bin/env bash
# install_netra_tools.sh
# Installs NETRA/KAIROS required Kali packages and ensures spiderfoot-cli command exists.
# Tested for Kali Rolling. Run as root:
#   sudo ./install_netra_tools.sh

set -euo pipefail
IFS=$'\n\t'

LOGFILE="/tmp/install_netra_tools_$(date +%Y%m%d_%H%M%S).log"
echo "Installation started at $(date -Iseconds)" | tee -a "$LOGFILE"

# Ensure script is run as root
if [ "$(id -u)" -ne 0 ]; then
  echo "ERROR: This script must be run as root (sudo)." | tee -a "$LOGFILE"
  exit 1
fi

echo "Updating apt package index..." | tee -a "$LOGFILE"
apt update -y 2>&1 | tee -a "$LOGFILE"

# APT package list (Kali packages)
APT_PACKAGES=(
  theharvester
  whois
  dnsutils             # nslookup
  geoip-bin            # geoiplookup
  geoip-database
  sherlock
  spiderfoot
  dirb
  dmitry
  emailharvester
  finalrecon
  linkedin2username
  metagoofil
  photon
  python3-pip
  python3-venv
  curl
  wget
  ca-certificates
)

echo "Installing apt packages..." | tee -a "$LOGFILE"
DEBIAN_FRONTEND=noninteractive apt -y install "${APT_PACKAGES[@]}" 2>&1 | tee -a "$LOGFILE" || {
  echo "apt install encountered errors. Trying to fix and retry..." | tee -a "$LOGFILE"
  apt -f install -y 2>&1 | tee -a "$LOGFILE"
  DEBIAN_FRONTEND=noninteractive apt -y install "${APT_PACKAGES[@]}" 2>&1 | tee -a "$LOGFILE" || {
    echo "ERROR: apt install failed again. Inspect $LOGFILE" | tee -a "$LOGFILE"
    exit 2
  }
}

# Ensure pip is up-to-date and install python deps
echo "Upgrading pip and installing Python dependencies..." | tee -a "$LOGFILE"
python3 -m pip install --upgrade pip 2>&1 | tee -a "$LOGFILE"
python3 -m pip install validators googlesearch-python beautifulsoup4 lxml requests tldextract 2>&1 | tee -a "$LOGFILE" || {
  echo "pip install warning: some packages may have failed to install. Check $LOGFILE." | tee -a "$LOGFILE"
}

# Ensure spiderfoot-cli exists. NETRA expects 'spiderfoot-cli' binary name.
# Typical Kali package provides 'spiderfoot' executable. We'll create a wrapper /usr/local/bin/spiderfoot-cli
ensure_spiderfoot_cli() {
  echo "Checking for spiderfoot/spiderfoot-cli..." | tee -a "$LOGFILE"
  if command -v spiderfoot-cli >/dev/null 2>&1; then
    echo "spiderfoot-cli already installed and in PATH." | tee -a "$LOGFILE"
    return 0
  fi

  if command -v spiderfoot >/dev/null 2>&1; then
    SF_BIN="$(command -v spiderfoot)"
    echo "Found spiderfoot at: $SF_BIN. Creating wrapper /usr/local/bin/spiderfoot-cli" | tee -a "$LOGFILE"
    cat > /usr/local/bin/spiderfoot-cli <<EOF
#!/usr/bin/env bash
# wrapper to call installed spiderfoot using the expected spiderfoot-cli name
exec "$SF_BIN" "\$@"
EOF
    chmod +x /usr/local/bin/spiderfoot-cli
    echo "Wrapper created: /usr/local/bin/spiderfoot-cli -> $SF_BIN" | tee -a "$LOGFILE"
    return 0
  fi

  # fallback: try pip install spiderfoot package (best-effort)
  echo "spiderfoot binary not found. Attempting pip install spiderfoot (fallback)..." | tee -a "$LOGFILE"
  if python3 -m pip install spiderfoot 2>&1 | tee -a "$LOGFILE"; then
    if command -v spiderfoot >/dev/null 2>&1; then
      SF_BIN="$(command -v spiderfoot)"
      echo "Pip-installed spiderfoot found at: $SF_BIN. Creating wrapper..." | tee -a "$LOGFILE"
      cat > /usr/local/bin/spiderfoot-cli <<EOF
#!/usr/bin/env bash
exec "$SF_BIN" "\$@"
EOF
      chmod +x /usr/local/bin/spiderfoot-cli
      echo "Wrapper created: /usr/local/bin/spiderfoot-cli" | tee -a "$LOGFILE"
      return 0
    else
      # Some pip installs put scripts under ~/.local/bin; try to locate
      if [ -d "/root/.local/bin" ] && ls /root/.local/bin/spiderfoot* >/dev/null 2>&1; then
        SF_BIN="/root/.local/bin/spiderfoot"
        cat > /usr/local/bin/spiderfoot-cli <<EOF
#!/usr/bin/env bash
exec "$SF_BIN" "\$@"
EOF
        chmod +x /usr/local/bin/spiderfoot-cli
        echo "Wrapper created for root-local spiderfoot: /usr/local/bin/spiderfoot-cli" | tee -a "$LOGFILE"
        return 0
      fi
    fi
  else
    echo "pip install spiderfoot fallback failed or spiderfoot still not in PATH." | tee -a "$LOGFILE"
  fi

  echo "WARNING: spiderfoot-cli could not be created automatically. Please ensure spiderfoot is installed and in PATH, or create a wrapper manually." | tee -a "$LOGFILE"
  return 1
}

ensure_spiderfoot_cli

# GeoIP verification
if command -v geoiplookup >/dev/null 2>&1; then
  echo "geoiplookup present: $(command -v geoiplookup)" | tee -a "$LOGFILE"
else
  echo "Warning: geoiplookup not found - geoip-bin/geoip-database install may have issues." | tee -a "$LOGFILE"
fi

# Verify commands
echo "Verifying installed commands (expected names used by NETRA)..." | tee -a "$LOGFILE"
CHECK_CMDS=(theHarvester whois nslookup geoiplookup sherlock spiderfoot spiderfoot-cli dirb dmitry EmailHarvester finalrecon linkedin2username metagoofil photon)
for c in "${CHECK_CMDS[@]}"; do
  if command -v "$c" >/dev/null 2>&1 ; then
    echo "  OK: $(command -v "$c")" | tee -a "$LOGFILE"
  else
    echo "  MISSING: $c (may be named differently; check package docs)" | tee -a "$LOGFILE"
  fi
done

# Post-install notes
cat <<'EOF' | tee -a "$LOGFILE"
Installation complete (attempted). Post-install checklist:
  * If any MISSING tools reported above, run:
      apt search <toolname>
    or inspect package names via `apt-cache policy <package>`
  * If EmailHarvester / Metagoofil still show ModuleNotFoundError, ensure pip packages were installed:
      python3 -m pip install validators googlesearch-python
  * spiderfoot-cli wrapper was created (if spiderfoot present). NETRA expects the 'spiderfoot-cli' command.
  * If you prefer isolated installs, use per-tool virtualenvs and install required pip packages there.
  * To update GeoIP2/GeoLite2 automatically you need a MaxMind account (not automated here).
EOF

echo "Log saved to: $LOGFILE"
echo "Done at $(date -Iseconds)" | tee -a "$LOGFILE"
