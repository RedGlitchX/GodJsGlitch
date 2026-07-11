#!/usr/bin/env python3
"""
GodJS - a self-contained JavaScript hunting engine.

Give it a domain; it discovers every associated JavaScript file it can reach:
  * live/linked JS (async crawler)
  * historical/deleted JS (Wayback, Common Crawl, OTX, URLScan)
  * lazy-loaded / hidden chunks (webpack / Vite / Next chunk-graph reconstruction)
  * original source revealed by source maps
Then analyzes each file for secrets + endpoints, ranks them, and optionally
validates secrets against live services (--validate, opt-in).

Design goals:
  * Single portable file. Copy it anywhere and run it.
  * No hard third-party dependency. Uses httpx if present (async), else requests,
    else stdlib urllib. Optional rich/tldextract/bs4 used only if importable.
  * No Go tools required. katana/gau/subfinder/subjs used only if on PATH.

Usage:
  python godjs.py example.com
  python godjs.py example.com --passive --validate --rebuild-src
  python godjs.py --check-deps
  python godjs.py --selftest

Authorized security testing only.
"""

from __future__ import annotations

import argparse
import asyncio
import base64
import hashlib
import hmac
import json
import math
import os
import re
import shutil
import socket
import ssl
import subprocess
import sys
import threading
import time
import urllib.parse
import urllib.request
from dataclasses import dataclass, field, asdict
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Callable, Optional

# ----------------------------------------------------------------------------
# Optional dependency detection (never required)
# ----------------------------------------------------------------------------
try:
    import httpx  # type: ignore
    HAVE_HTTPX = True
except Exception:
    HAVE_HTTPX = False

try:
    import requests  # type: ignore
    HAVE_REQUESTS = True
except Exception:
    HAVE_REQUESTS = False

try:
    import tldextract  # type: ignore
    HAVE_TLDEXTRACT = True
except Exception:
    HAVE_TLDEXTRACT = False

try:
    from bs4 import BeautifulSoup  # type: ignore
    HAVE_BS4 = True
except Exception:
    HAVE_BS4 = False

try:
    import rich  # type: ignore  # noqa: F401
    HAVE_RICH = True
except Exception:
    HAVE_RICH = False


# ----------------------------------------------------------------------------
# Selftest harness (dependency-free; runs via `python godjs.py --selftest`)
# ----------------------------------------------------------------------------
_SELFTESTS: "list[tuple[str, Callable[[], None]]]" = []


def selftest(name: str):
    """Register a zero-arg check function under `name` for --selftest."""
    def deco(fn: "Callable[[], None]") -> "Callable[[], None]":
        _SELFTESTS.append((name, fn))
        return fn
    return deco


def run_selftests(pattern: "Optional[str]" = None) -> int:
    """Run registered selftests (optionally filtered by substring). Return #failures."""
    fails = 0
    ran = 0
    for name, fn in _SELFTESTS:
        if pattern and pattern not in name:
            continue
        ran += 1
        try:
            fn()
            print(f"  PASS  {name}")
        except Exception as e:  # noqa: BLE001 - report and continue
            fails += 1
            import traceback
            print(f"  FAIL  {name}: {type(e).__name__}: {e}")
            if os.environ.get("GODJS_TRACE"):
                traceback.print_exc()
    print(f"\n{ran} tests run, {fails} failed")
    return fails


# ----------------------------------------------------------------------------
# Test helpers (used only by selftests; harmless in production)
# ----------------------------------------------------------------------------
def _run(coro):
    """Run a coroutine to completion on a fresh event loop (test helper)."""
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


def _serve(routes: dict):
    """Spin a local HTTP server for tests.

    routes: {path: (content_type, body_bytes)}
    Returns (base_url, stop_fn).
    """
    class _H(BaseHTTPRequestHandler):
        def log_message(self, *a):  # silence
            pass

        def do_GET(self):
            path = urllib.parse.urlsplit(self.path).path
            if path in routes:
                ctype, body = routes[path]
                self.send_response(200)
                self.send_header("Content-Type", ctype)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
            else:
                self.send_response(404)
                self.end_headers()
                self.wfile.write(b"not found")

        def do_HEAD(self):
            path = urllib.parse.urlsplit(self.path).path
            if path in routes:
                ctype, body = routes[path]
                self.send_response(200)
                self.send_header("Content-Type", ctype)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
            else:
                self.send_response(404)
                self.end_headers()

    srv = ThreadingHTTPServer(("127.0.0.1", 0), _H)
    port = srv.server_address[1]
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    base = f"http://127.0.0.1:{port}"

    def stop():
        srv.shutdown()
        srv.server_close()

    return base, stop


def _host(url: str) -> str:
    """Return the host[:port]-free hostname of a URL (test helper)."""
    return urllib.parse.urlsplit(url).hostname or ""


@selftest("harness.sanity")
def _t_harness():
    assert 1 + 1 == 2
    base, stop = _serve({"/x": ("text/plain", b"ok")})
    try:
        with urllib.request.urlopen(base + "/x", timeout=5) as r:
            assert r.read() == b"ok"
    finally:
        stop()


# ----------------------------------------------------------------------------
# SECTION: URL canonicalization, JS detection, Scope guardrails
# ----------------------------------------------------------------------------
_JS_RE = re.compile(r"\.(m?js|jsx|cjs)(\?|#|$)", re.I)
_IP_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")

# Common multi-label public suffixes so apex parsing works without tldextract.
_MULTI_TLDS = {
    "co.uk", "org.uk", "gov.uk", "ac.uk", "me.uk",
    "co.jp", "or.jp", "ne.jp", "gr.jp", "ac.jp",
    "co.in", "co.kr", "co.za", "co.nz", "co.id", "co.th", "co.il",
    "com.au", "net.au", "org.au", "com.br", "com.co", "com.mx", "com.ar",
    "com.tr", "com.cn", "com.tw", "com.hk", "com.sg", "com.my", "com.sa",
    "com.eg", "com.ng", "com.ua", "com.pk", "com.ph", "com.vn",
}


def looks_like_js_url(u: str) -> bool:
    """True if the URL path looks like a JavaScript resource."""
    path = urllib.parse.urlsplit(u).path
    return bool(_JS_RE.search(path))


def canonicalize_url(u: str, base: "Optional[str]" = None) -> str:
    """Absolutize (against base), lowercase host, drop default port + fragment."""
    u = u.strip()
    if base:
        u = urllib.parse.urljoin(base, u)
    parts = urllib.parse.urlsplit(u)
    scheme = (parts.scheme or "http").lower()
    host = (parts.hostname or "").lower()
    try:
        port = parts.port
    except ValueError:
        port = None
    if port and not ((scheme == "http" and port == 80) or (scheme == "https" and port == 443)):
        netloc = f"{host}:{port}"
    else:
        netloc = host
    return urllib.parse.urlunsplit((scheme, netloc, parts.path or "", parts.query, ""))


def apex_of(host: str) -> str:
    """Return the registrable apex domain for a host (or the host itself for IPs)."""
    host = host.lower().strip(".")
    if not host or _IP_RE.match(host):
        return host
    if HAVE_TLDEXTRACT:
        try:
            ext = tldextract.extract(host)
            if ext.domain and ext.suffix:
                return f"{ext.domain}.{ext.suffix}"
        except Exception:
            pass
    labels = host.split(".")
    if len(labels) <= 2:
        return host
    if ".".join(labels[-2:]) in _MULTI_TLDS:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


@dataclass
class Scope:
    """Apex-scoped guardrail: decides whether a URL is in-scope."""
    apex: str
    allow_subs: bool = True
    oos: set = field(default_factory=set)

    def __post_init__(self):
        self.apex = apex_of(self.apex)
        self.oos = {h.lower() for h in self.oos}

    def add_oos(self, host: str) -> None:
        self.oos.add(host.lower())

    def in_scope(self, url: str) -> bool:
        host = _host(url).lower()
        if not host or host in self.oos:
            return False
        if host == self.apex:
            return True
        if self.allow_subs and host.endswith("." + self.apex):
            return True
        return False


@selftest("url.canonicalize")
def _t_canon():
    assert canonicalize_url("app.js", "https://x.com/a/b") == "https://x.com/a/app.js"
    assert canonicalize_url("https://X.com:443/p?q=1#f") == "https://x.com/p?q=1"
    assert canonicalize_url("/y.js", "https://x.com/a/b") == "https://x.com/y.js"
    # idempotent
    once = canonicalize_url("https://X.com:8080/A?b=1#c")
    assert canonicalize_url(once) == once == "https://x.com:8080/A?b=1"


@selftest("url.looks_like_js")
def _t_js():
    assert looks_like_js_url("https://x.com/a.js?v=2")
    assert looks_like_js_url("https://x.com/a.chunk.mjs")
    assert looks_like_js_url("https://x.com/path/to/bundle.cjs")
    assert not looks_like_js_url("https://x.com/a.css")
    assert not looks_like_js_url("https://x.com/a.json")


@selftest("scope.apex_and_membership")
def _t_scope():
    assert apex_of("a.b.example.co.uk") == "example.co.uk"
    assert apex_of("cdn.example.com") == "example.com"
    assert apex_of("127.0.0.1") == "127.0.0.1"
    s = Scope("example.com", allow_subs=True)
    assert s.in_scope("https://cdn.example.com/x.js")
    assert s.in_scope("https://example.com/x.js")
    assert not s.in_scope("https://evil.com/x.js")
    assert not s.in_scope("https://notexample.com/x.js")
    s2 = Scope("example.com", allow_subs=False)
    assert not s2.in_scope("https://cdn.example.com/x.js")
    assert s2.in_scope("https://example.com/x.js")
    s.add_oos("cdn.example.com")
    assert not s.in_scope("https://cdn.example.com/x.js")


# @@INSERT_SECTIONS_ABOVE@@


# ----------------------------------------------------------------------------
# CLI / entrypoint
# ----------------------------------------------------------------------------
def cmd_check_deps() -> int:
    print("GodJS dependency report")
    print("  python        :", sys.version.split()[0])
    print("  httpx         :", "yes" if HAVE_HTTPX else "no (fallback: requests/urllib)")
    print("  requests      :", "yes" if HAVE_REQUESTS else "no")
    print("  tldextract    :", "yes" if HAVE_TLDEXTRACT else "no (fallback: builtin TLD heuristic)")
    print("  beautifulsoup4:", "yes" if HAVE_BS4 else "no (fallback: regex HTML parsing)")
    print("  rich          :", "yes" if HAVE_RICH else "no (plain output)")
    for tool in ("katana", "gau", "subfinder", "subjs", "waybackurls"):
        print(f"  {tool:<14}:", "on PATH" if shutil.which(tool) else "absent (native fallback)")
    return 0


def build_argparser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="godjs",
        description="GodJS - hunt every JavaScript file for a domain.",
    )
    p.add_argument("domain", nargs="?", help="target domain, e.g. example.com")
    p.add_argument("--selftest", nargs="?", const="", metavar="PATTERN",
                   help="run built-in offline tests (optional substring filter) and exit")
    p.add_argument("--check-deps", action="store_true",
                   help="report available optional libs/tools and exit")
    return p


def main(argv=None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    ns = build_argparser().parse_args(argv)
    if ns.selftest is not None:
        return 1 if run_selftests(ns.selftest or None) else 0
    if ns.check_deps:
        return cmd_check_deps()
    if not ns.domain:
        build_argparser().print_help()
        return 2
    print("[godjs] full run not wired yet (built incrementally); use --selftest for now")
    return 0


if __name__ == "__main__":
    sys.exit(main())
