#!/usr/bin/env bash
#
# GodJsGlitch - Linux setup.
#
# Creates a self-contained virtualenv with all optional deps so every feature
# works out of the box (including --render, which needs pip's Playwright that
# bundles its own Node.js - avoiding the apt python3-playwright / missing-node
# problem entirely).
#
# Usage:
#   ./setup.sh                 core install (httpx, tldextract, bs4, rich)
#   ./setup.sh --with-render   also Playwright + Chromium (headless --render)
#   ./setup.sh --with-tools    also subfinder / katana (recon bridge)
#   ./setup.sh --all           everything
#
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
VENV="$HERE/.venv"
RENDER=0
TOOLS=0

for a in "$@"; do
  case "$a" in
    --with-render) RENDER=1 ;;
    --with-tools)  TOOLS=1 ;;
    --all)         RENDER=1; TOOLS=1 ;;
    -h|--help)
      echo "usage: ./setup.sh [--with-render] [--with-tools] [--all]"; exit 0 ;;
    *) echo "unknown option: $a"; exit 2 ;;
  esac
done

if [ "$(uname -s)" != "Linux" ]; then
  echo "[!] setup.sh targets Linux. On other OSes, run godjs.py directly with Python 3.9+."
fi

command -v python3 >/dev/null || { echo "[x] python3 not found. Install it first."; exit 1; }

echo "[*] Creating virtualenv: $VENV"
python3 -m venv "$VENV"
"$VENV/bin/pip" install --quiet --upgrade pip

echo "[*] Installing core dependencies (httpx, tldextract, beautifulsoup4, rich)"
"$VENV/bin/pip" install --quiet httpx tldextract beautifulsoup4 rich

if [ "$RENDER" = "1" ]; then
  echo "[*] Installing Playwright (bundles its own Node.js) + Chromium"
  "$VENV/bin/pip" install --quiet playwright
  "$VENV/bin/playwright" install chromium
  if command -v sudo >/dev/null 2>&1; then
    echo "[*] Installing Chromium system libraries (sudo)"
    sudo "$VENV/bin/playwright" install-deps chromium || \
      echo "[!] install-deps failed - if --render errors on missing libs, install them manually"
  else
    echo "[!] no sudo; if --render fails on missing libs run: $VENV/bin/playwright install-deps chromium"
  fi
fi

if [ "$TOOLS" = "1" ]; then
  echo "[*] Installing recon tools (optional bridge: subfinder, katana)"
  if command -v apt-get >/dev/null 2>&1; then
    sudo apt-get update -qq && sudo apt-get install -y subfinder katana 2>/dev/null || \
      echo "[!] apt install of subfinder/katana failed (not fatal - native fallbacks cover them)"
  fi
  if command -v go >/dev/null 2>&1; then
    go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest 2>/dev/null || true
    go install github.com/projectdiscovery/katana/cmd/katana@latest 2>/dev/null || true
  fi
fi

chmod +x "$HERE/godjs.py"

echo
echo "[+] Setup complete."
echo
echo "    Activate the venv, then run:"
echo "        source \"$VENV/bin/activate\""
echo "        ./godjs.py <domain> --verbose"
echo
echo "    Or without activating:"
echo "        \"$VENV/bin/python\" godjs.py <domain> --verbose"
echo
echo "    Verify what's available:"
echo "        \"$VENV/bin/python\" godjs.py --check-deps"
