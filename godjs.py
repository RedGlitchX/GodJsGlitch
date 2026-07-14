#!/usr/bin/env python3
"""
GodJsGlitch - a self-contained JavaScript hunting engine.

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

Built for Linux (Kali/Debian). Runs anywhere Python 3.9+ runs; use ./setup.sh on Linux.

Usage:
  ./godjs.py example.com
  ./godjs.py example.com --render --validate --verbose
  ./godjs.py --check-deps
  ./godjs.py --selftest

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
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field, asdict, replace
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

try:
    from playwright.async_api import async_playwright  # type: ignore
    HAVE_PLAYWRIGHT = True
except Exception:
    HAVE_PLAYWRIGHT = False


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
    """Apex-scoped guardrail: decides whether a URL is in-scope.

    If `allow_hosts` is non-empty (e.g. from --scope FILE) it takes precedence:
    a URL is in scope only if its host equals or is a subdomain of a listed host.
    Otherwise the apex + allow_subs logic applies.
    """
    apex: str
    allow_subs: bool = True
    oos: set = field(default_factory=set)
    allow_hosts: set = field(default_factory=set)

    def __post_init__(self):
        # `apex` may arrive as a bare host, a subdomain, or a full URL. Remember the
        # EXACT target host (so it is always in scope, even with allow_subs=False),
        # then collapse to the registrable apex for subdomain matching.
        raw = (self.apex or "").strip().lower()
        if "://" in raw:
            raw = raw.split("://", 1)[1]
        raw = raw.split("/", 1)[0].split("@")[-1].split(":")[0].strip(".")
        self.target = raw
        self.apex = apex_of(raw)
        self.oos = {h.lower() for h in self.oos}
        self.allow_hosts = {h.lower().lstrip("*.") for h in self.allow_hosts}

    def add_oos(self, host: str) -> None:
        self.oos.add(host.lower())

    def in_scope(self, url: str) -> bool:
        host = _host(url).lower()
        if not host or host in self.oos:
            return False
        if self.allow_hosts:
            return any(host == h or host.endswith("." + h) for h in self.allow_hosts)
        # The exact target host is ALWAYS in scope, even a subdomain under --no-subs
        # (otherwise a per-host hunt on `docs.example.com` excludes its own homepage).
        if host == self.target or host == self.apex:
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
    # A subdomain target with --no-subs must include ITS OWN host (per-host mode).
    s3 = Scope("docs.example.com", allow_subs=False)
    assert s3.in_scope("https://docs.example.com/_static/app.js")   # own host
    assert s3.in_scope("https://example.com/x.js")                  # apex (redirect target)
    assert not s3.in_scope("https://cdn.example.com/x.js")          # sibling stays out
    # Accepts a full URL / scheme as the target spec too.
    s4 = Scope("https://api.example.com/", allow_subs=False)
    assert s4.in_scope("https://api.example.com/v1/bundle.js")
    s.add_oos("cdn.example.com")
    assert not s.in_scope("https://cdn.example.com/x.js")


# ----------------------------------------------------------------------------
# SECTION: Config + async HttpEngine (httpx -> requests -> urllib fallback)
# ----------------------------------------------------------------------------
DEFAULT_UA = ("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
              "(KHTML, like Gecko) Chrome/124.0 Safari/537.36")


@dataclass
class Config:
    """Runtime configuration. Expanded/parsed from CLI in Config.from_args (Task 14)."""
    domain: str = ""
    seeds: list = field(default_factory=list)
    allow_subs: bool = True
    passive: bool = False
    depth: int = 2
    max_urls: int = 5000
    max_pages: int = 300
    concurrency: int = 20
    rate: float = 10.0            # max requests/sec per host
    timeout: float = 15.0
    retries: int = 1
    passive_budget: float = 45.0  # overall wall-clock cap for passive providers
    proxy: "Optional[str]" = None
    headers: dict = field(default_factory=dict)
    ua: str = DEFAULT_UA
    validate: bool = False
    rebuild_src: bool = False
    no_analyze: bool = False
    render: bool = False
    render_pages: int = 25
    per_host: bool = False
    host_concurrency: int = 4
    skip_archives: bool = False
    extra_candidates: list = field(default_factory=list)
    outdir: "Optional[str]" = None
    scope_file: "Optional[str]" = None
    json_only: bool = False
    verbose: int = 0

    @classmethod
    def defaults(cls) -> "Config":
        return cls()

    @classmethod
    def from_args(cls, ns: argparse.Namespace) -> "Config":
        headers: dict = {}
        for h in (getattr(ns, "header", None) or []):
            if ":" in h:
                k, v = h.split(":", 1)
                headers[k.strip()] = v.strip()
        return cls(
            domain=ns.domain or "",
            allow_subs=not ns.no_subs,
            passive=ns.passive,
            depth=ns.depth,
            max_urls=ns.max_urls,
            max_pages=ns.max_pages,
            concurrency=ns.concurrency,
            rate=ns.rate,
            timeout=ns.timeout,
            passive_budget=ns.passive_timeout,
            proxy=ns.proxy,
            headers=headers,
            ua=ns.ua or DEFAULT_UA,
            validate=ns.validate,
            rebuild_src=ns.rebuild_src,
            no_analyze=ns.no_analyze,
            render=ns.render,
            render_pages=ns.render_pages,
            per_host=ns.per_host,
            host_concurrency=ns.host_concurrency,
            outdir=ns.outdir,
            scope_file=ns.scope,
            json_only=ns.json_only,
            verbose=ns.verbose,
        )


@dataclass
class Response:
    url: str
    status: "Optional[int]"
    headers: dict
    text: str
    content: bytes
    error: "Optional[str]"
    final_url: str


class HttpEngine:
    """Async HTTP with backend fallback, per-host rate limiting, retries, proxy."""

    def __init__(self, cfg: Config):
        self.cfg = cfg
        self._sem = asyncio.Semaphore(max(1, cfg.concurrency))
        self._host_last: "dict[str, float]" = {}
        self._host_locks: "dict[str, asyncio.Lock]" = {}
        self._client = None  # lazy httpx.AsyncClient
        if HAVE_HTTPX:
            self.backend = "httpx"
        elif HAVE_REQUESTS:
            self.backend = "requests"
        else:
            self.backend = "urllib"

    def _headers(self) -> dict:
        # Browser-like headers reduce trivial WAF/bot 403s on protected sites.
        h = {
            "User-Agent": self.cfg.ua,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,"
                      "image/avif,image/webp,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
            "Sec-Fetch-Dest": "document",
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-Site": "none",
            "Sec-Fetch-User": "?1",
            "Upgrade-Insecure-Requests": "1",
        }
        h.update(self.cfg.headers or {})
        return h

    async def _rate_wait(self, host: str) -> None:
        if self.cfg.rate <= 0:
            return
        lock = self._host_locks.get(host)
        if lock is None:
            lock = asyncio.Lock()
            self._host_locks[host] = lock
        async with lock:
            interval = 1.0 / self.cfg.rate
            now = time.monotonic()
            wait = interval - (now - self._host_last.get(host, 0.0))
            if wait > 0:
                await asyncio.sleep(wait)
            self._host_last[host] = time.monotonic()

    async def _ensure_httpx(self):
        if self._client is None:
            kw = dict(verify=False, follow_redirects=True, timeout=self.cfg.timeout)
            if self.cfg.proxy:
                try:
                    self._client = httpx.AsyncClient(proxy=self.cfg.proxy, **kw)
                except TypeError:
                    self._client = httpx.AsyncClient(proxies=self.cfg.proxy, **kw)
            else:
                self._client = httpx.AsyncClient(**kw)
        return self._client

    async def _fetch_httpx(self, method: str, url: str) -> Response:
        client = await self._ensure_httpx()
        resp = await client.request(method, url, headers=self._headers())
        text = resp.text if method == "GET" else ""
        content = resp.content if method == "GET" else b""
        return Response(url, resp.status_code, dict(resp.headers), text, content, None, str(resp.url))

    def _fetch_requests_sync(self, method: str, url: str) -> Response:
        try:
            import urllib3  # type: ignore
            urllib3.disable_warnings()
        except Exception:
            pass
        proxies = {"http": self.cfg.proxy, "https": self.cfg.proxy} if self.cfg.proxy else None
        r = requests.request(method, url, headers=self._headers(), timeout=self.cfg.timeout,
                             allow_redirects=True, verify=False, proxies=proxies)
        content = r.content if method == "GET" else b""
        text = r.text if method == "GET" else ""
        return Response(url, r.status_code, dict(r.headers), text, content, None, r.url)

    def _fetch_urllib_sync(self, method: str, url: str) -> Response:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        handlers = [urllib.request.HTTPSHandler(context=ctx)]
        if self.cfg.proxy:
            handlers.append(urllib.request.ProxyHandler(
                {"http": self.cfg.proxy, "https": self.cfg.proxy}))
        opener = urllib.request.build_opener(*handlers)
        req = urllib.request.Request(url, method=method, headers=self._headers())
        try:
            with opener.open(req, timeout=self.cfg.timeout) as r:
                content = r.read() if method == "GET" else b""
                text = content.decode("utf-8", "replace") if method == "GET" else ""
                return Response(url, getattr(r, "status", 200), dict(r.headers), text, content, None, r.geturl())
        except urllib.error.HTTPError as e:
            body = e.read() if method == "GET" else b""
            return Response(url, e.code, dict(e.headers or {}),
                            body.decode("utf-8", "replace"), body, None, url)

    async def _dispatch(self, method: str, url: str) -> Response:
        if self.backend == "httpx":
            return await self._fetch_httpx(method, url)
        if self.backend == "requests":
            return await asyncio.to_thread(self._fetch_requests_sync, method, url)
        return await asyncio.to_thread(self._fetch_urllib_sync, method, url)

    @staticmethod
    def _no_retry(e: Exception) -> bool:
        """DNS failures and timeouts won't succeed on retry - and retrying doubles the wait."""
        if isinstance(e, (socket.gaierror, socket.timeout, TimeoutError)):
            return True
        m = str(e).lower()
        return any(s in m for s in (
            "getaddrinfo", "name or service not known", "nodename nor servname",
            "temporary failure in name resolution", "no address associated",
            "name does not resolve", "timeout", "timed out"))

    async def _request(self, method: str, url: str) -> Response:
        host = _host(url)
        async with self._sem:
            await self._rate_wait(host)
            last_err = None
            for attempt in range(self.cfg.retries + 1):
                try:
                    return await self._dispatch(method, url)
                except Exception as e:  # noqa: BLE001 - network error -> maybe retry, then record
                    last_err = e
                    if self._no_retry(e) or attempt >= self.cfg.retries:
                        break
                    await asyncio.sleep(0.2 * (attempt + 1))
            return Response(url, None, {}, "", b"",
                            f"{type(last_err).__name__}: {last_err}", url)

    async def get(self, url: str) -> Response:
        return await self._request("GET", url)

    async def head(self, url: str) -> Response:
        return await self._request("HEAD", url)

    async def close(self) -> None:
        if self._client is not None:
            try:
                await self._client.aclose()
            except Exception:
                pass
            self._client = None


@selftest("http.get_ok_and_error")
def _t_http():
    base, stop = _serve({"/a.js": ("application/javascript", b"var a=1;")})

    async def go():
        eng = HttpEngine(Config.defaults())
        try:
            r = await eng.get(base + "/a.js")
            r2 = await eng.get(base + "/missing")
            r3 = await eng.get("http://127.0.0.1:1/x")  # closed port
            return r, r2, r3
        finally:
            await eng.close()

    try:
        r, r2, r3 = _run(go())
        assert r.status == 200 and "var a=1" in r.text
        assert r2.status == 404
        assert r3.error is not None and r3.status is None
    finally:
        stop()


# ----------------------------------------------------------------------------
# SECTION: Prober (liveness/metadata, real-JS sniffing, content-hash dedup)
# ----------------------------------------------------------------------------
def _header(headers: dict, name: str) -> str:
    name = name.lower()
    for k, v in (headers or {}).items():
        if k.lower() == name:
            return v
    return ""


@dataclass
class FileRecord:
    url: str
    sources: set
    http_status: "Optional[int]"
    content_type: str
    bytes: int
    sha256: str
    is_js: bool
    text: str
    revealed_sources: list = field(default_factory=list)
    sourcemap_url: "Optional[str]" = None
    secrets: list = field(default_factory=list)
    endpoints: list = field(default_factory=list)
    score: float = 0.0
    validated: list = field(default_factory=list)


def is_real_js(content_type: str, body_head: str, url: str = "") -> bool:
    """Decide if a fetched resource is genuinely JavaScript (not HTML masquerading)."""
    ct = (content_type or "").lower()
    if "javascript" in ct or "ecmascript" in ct:
        return True
    head = (body_head or "").lstrip().lower()[:200]
    if head.startswith("<!doctype") or head.startswith("<html") or head.startswith("<head"):
        return False
    if looks_like_js_url(url):
        if ct.startswith("text/html"):
            return False
        return True
    return False


class Prober:
    """Fetches a candidate, records metadata, dedups by content hash."""

    def __init__(self, engine: HttpEngine):
        self.engine = engine
        self.seen_hashes: set = set()

    async def probe(self, url: str, via: str) -> "Optional[FileRecord]":
        r = await self.engine.get(url)
        if r.error or r.status is None or r.status != 200:
            return None
        body = r.content if r.content else (r.text or "").encode("utf-8", "replace")
        sha = hashlib.sha256(body).hexdigest()
        if sha in self.seen_hashes:
            return None
        self.seen_hashes.add(sha)
        ctype = _header(r.headers, "content-type")
        isjs = is_real_js(ctype, r.text or "", url)
        return FileRecord(url, {via}, r.status, ctype, len(body), sha, isjs, r.text or "")


@selftest("prober.detect_and_dedup")
def _t_probe():
    base, stop = _serve({
        "/real.js": ("application/javascript", b"export const x=1"),
        "/dupe.js": ("application/javascript", b"export const x=1"),   # same body -> dedup
        "/fake.js": ("text/html", b"<!doctype html><html></html>"),
    })

    async def go():
        p = Prober(HttpEngine(Config.defaults()))
        r1 = await p.probe(base + "/real.js", "test")
        r2 = await p.probe(base + "/dupe.js", "test")
        r3 = await p.probe(base + "/fake.js", "test")
        await p.engine.close()
        return r1, r2, r3

    try:
        r1, r2, r3 = _run(go())
        assert r1 is not None and r1.is_js and r1.sha256
        assert r2 is None                       # deduped by content hash
        assert r3 is not None and not r3.is_js   # HTML served at .js -> not JS
    finally:
        stop()


# ----------------------------------------------------------------------------
# SECTION: Source-map mining (reveal the original module tree)
# ----------------------------------------------------------------------------
_SMAP_RE = re.compile(r"//[#@]\s*sourceMappingURL=(\S+)")


def find_sourcemap_url(js_text: str, base: str) -> "Optional[str]":
    """Return the sourceMappingURL declared in a JS file (absolutized), or None.

    Data-URI source maps are returned verbatim (caller decodes with
    sourcemap_from_datauri). The `.map`-by-convention fallback is handled by the
    orchestrator, which additionally probes `<js_url>.map`.
    """
    last = None
    for last in _SMAP_RE.finditer(js_text):
        pass
    if not last:
        return None
    u = last.group(1).strip()
    if u.startswith("data:"):
        return u
    return canonicalize_url(u, base)


def sourcemap_from_datauri(u: str) -> str:
    """Decode an inline `data:` source map into its JSON text."""
    try:
        header, payload = u.split(",", 1)
        if ";base64" in header:
            return base64.b64decode(payload).decode("utf-8", "replace")
        return urllib.parse.unquote(payload)
    except Exception:
        return ""


def parse_sourcemap(text: str) -> dict:
    """Parse a source map JSON into a normalized dict (guarded)."""
    try:
        data = json.loads(text)
    except Exception:
        return {"sources": [], "sourcesContent": None, "sourceRoot": ""}
    return {
        "sources": data.get("sources") or [],
        "sourcesContent": data.get("sourcesContent"),
        "sourceRoot": data.get("sourceRoot") or "",
    }


def revealed_source_paths(smap: dict, base: str) -> "list[str]":
    """Turn a parsed source map's sources[] into revealed original paths."""
    root = smap.get("sourceRoot") or ""
    out: "list[str]" = []
    for s in smap.get("sources") or []:
        if not s:
            continue
        if s.startswith("webpack://") or "://" in s:
            out.append(s)  # keep marker verbatim
        else:
            out.append(root + s if root else s)
    return out


@selftest("sourcemap.find_and_parse")
def _t_smap():
    js = "var a=1;\n//# sourceMappingURL=app.js.map"
    assert find_sourcemap_url(js, "https://x.com/s/app.js") == "https://x.com/s/app.js.map"
    assert find_sourcemap_url("no map here", "https://x.com/a.js") is None
    smap = parse_sourcemap(
        '{"version":3,"sources":["../src/secret.ts","webpack://app/./util.js"],"sourceRoot":""}')
    paths = revealed_source_paths(smap, "https://x.com/s/app.js.map")
    assert any("secret.ts" in p for p in paths)
    assert any(p.startswith("webpack://") for p in paths)
    # inline data-URI map decodes
    b64 = base64.b64encode(b'{"version":3,"sources":["../src/inline.ts"]}').decode()
    text = sourcemap_from_datauri("data:application/json;base64," + b64)
    assert "inline.ts" in text


# ----------------------------------------------------------------------------
# SECTION: Webpack / Vite / Next chunk-graph reconstruction (hidden chunks)
# ----------------------------------------------------------------------------
_PP_RE = re.compile(r"\.p\s*=\s*[\"']([^\"']*)[\"']")


def _balanced(s: str, i: int) -> "Optional[str]":
    """Given s[i] == '{', return the inner text of the balanced {...} (quote-aware)."""
    if i < 0 or i >= len(s) or s[i] != "{":
        return None
    depth = 0
    quote = None
    j = i
    while j < len(s):
        c = s[j]
        if quote:
            if c == quote and s[j - 1] != "\\":
                quote = None
        elif c in "\"'":
            quote = c
        elif c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                return s[i + 1:j]
        j += 1
    return None


def _read_expr(s: str) -> str:
    """Read an expression up to the first top-level ';' (quote/bracket aware)."""
    depth = 0
    quote = None
    for j, c in enumerate(s):
        if quote:
            if c == quote and s[j - 1] != "\\":
                quote = None
        elif c in "\"'":
            quote = c
        elif c in "([{":
            depth += 1
        elif c in ")]}":
            depth -= 1
        elif c == ";" and depth == 0:
            return s[:j]
    return s


def _split_top_plus(expr: str) -> "list[str]":
    """Split a JS concatenation expression on top-level '+' (quote/bracket aware)."""
    parts = []
    depth = 0
    quote = None
    cur = ""
    i = 0
    while i < len(expr):
        c = expr[i]
        if quote:
            cur += c
            if c == quote and expr[i - 1] != "\\":
                quote = None
        elif c in "\"'":
            quote = c
            cur += c
        elif c in "([{":
            depth += 1
            cur += c
        elif c in ")]}":
            depth -= 1
            cur += c
        elif c == "+" and depth == 0:
            parts.append(cur)
            cur = ""
        else:
            cur += c
        i += 1
    parts.append(cur)
    return [p.strip() for p in parts if p.strip()]


def _find_u_template(js: str):
    """Locate webpack's chunk-URL template `.u`. Returns (param, return_expr)."""
    for m in re.finditer(r"\.u\s*=\s*function\s*\(([^)]*)\)\s*\{", js):
        param = m.group(1).strip().split(",")[0].strip()
        body = _balanced(js, m.end() - 1)
        if body is None:
            continue
        mm = re.match(r"\s*return\s*(.*)", body.strip(), re.S)
        return param, (mm.group(1) if mm else body).strip()
    for m in re.finditer(r"\.u\s*=\s*\(?([A-Za-z_$][\w$]*)\)?\s*=>\s*", js):
        param = m.group(1)
        rest = js[m.end():]
        if rest.lstrip().startswith("{"):
            body = _balanced(rest, rest.index("{")) or ""
            mm = re.search(r"return\s*(.*)", body.strip(), re.S)
            expr = (mm.group(1) if mm else body).strip()
        else:
            expr = _read_expr(rest).strip()
        return param, expr
    return None, None


def _find_chunk_hashmap(text: str) -> dict:
    """Find a `{id:"hash", ...}` object literal (numeric keys -> string values)."""
    for m in re.finditer(r"\{([^{}]*)\}", text):
        inner = m.group(1)
        if not inner.strip() or ":" not in inner:
            continue
        pairs = re.findall(r'(\d+)\s*:\s*"([^"]*)"', inner)
        if not pairs:
            pairs = re.findall(r"(\d+)\s*:\s*'([^']*)'", inner)
        if pairs and len(pairs) == inner.count(":"):
            return {int(k): v for k, v in pairs}
    return {}


def _eval_term(term: str, param: str, cid: int, hashmap: dict) -> str:
    term = term.strip()
    if len(term) >= 2 and term[0] in "\"'" and term[-1] == term[0]:
        return term[1:-1]
    if term == param:
        return str(cid)
    if re.search(r"\[\s*" + re.escape(param) + r"\s*\]\s*$", term):
        return str(hashmap.get(cid, cid))
    if param in term and hashmap.get(cid):
        return str(hashmap.get(cid))
    if re.fullmatch(r"\d+", term):
        return term
    return ""


def reconstruct_webpack_chunks(js_text: str, base: str) -> "set[str]":
    """Reconstruct every lazy webpack chunk URL from the runtime bundle."""
    urls: "set[str]" = set()
    try:
        pp_m = _PP_RE.search(js_text)
        pp = pp_m.group(1) if pp_m else ""
        param, expr = _find_u_template(js_text)
        if not expr or not param:
            return urls
        hashmap = _find_chunk_hashmap(expr) or _find_chunk_hashmap(js_text)
        if not hashmap:
            return urls
        terms = _split_top_plus(expr)
        for cid in hashmap:
            out = "".join(_eval_term(t, param, cid, hashmap) for t in terms)
            if out:
                urls.add(canonicalize_url(pp + out, base))
    except Exception:
        pass
    return urls


def parse_asset_manifest(json_text: str, base: str) -> "set[str]":
    """Parse a CRA-style asset-manifest.json / chunk-manifest.json for JS URLs."""
    urls: "set[str]" = set()
    try:
        data = json.loads(json_text)
    except Exception:
        return urls

    def walk(v):
        if isinstance(v, str):
            if v.endswith(".js") or looks_like_js_url(v):
                urls.add(canonicalize_url(v, base))
        elif isinstance(v, dict):
            for x in v.values():
                walk(x)
        elif isinstance(v, list):
            for x in v:
                walk(x)

    walk(data)
    return urls


def parse_vite_manifest(json_text: str, base: str) -> "set[str]":
    """Parse a Vite .vite/manifest.json for emitted JS files."""
    urls: "set[str]" = set()
    try:
        data = json.loads(json_text)
    except Exception:
        return urls
    if isinstance(data, dict):
        for entry in data.values():
            if isinstance(entry, dict):
                for key in ("file", "src"):
                    v = entry.get(key)
                    if isinstance(v, str) and v.endswith(".js"):
                        urls.add(canonicalize_url(v, base))
    return urls


def parse_next_build_manifest(js_text: str, base: str) -> "set[str]":
    """Parse Next.js _buildManifest.js / any manifest-ish JS for chunk paths."""
    urls: "set[str]" = set()
    for m in re.finditer(r'["\']([^"\']+\.js)["\']', js_text):
        p = m.group(1)
        if p.startswith("static/"):
            urls.add(canonicalize_url("/_next/" + p, base))
        else:
            urls.add(canonicalize_url(p, base))
    return urls


@selftest("webpack.reconstruct")
def _t_wp():
    runtime = ('a.p="/static/";t.u=function(e){return"js/"+e+"."+'
               '{12:"deadbeef",7:"c0ffee"}[e]+".chunk.js"}')
    urls = reconstruct_webpack_chunks(runtime, "https://x.com/static/js/main.js")
    assert "https://x.com/static/js/12.deadbeef.chunk.js" in urls, urls
    assert "https://x.com/static/js/7.c0ffee.chunk.js" in urls, urls


@selftest("manifest.asset_vite_next")
def _t_mani():
    assert "https://x.com/static/js/2.abc.chunk.js" in parse_asset_manifest(
        '{"files":{"static/js/2.abc.chunk.js":"/static/js/2.abc.chunk.js"}}',
        "https://x.com/asset-manifest.json")
    assert any("index.9f.js" in u for u in parse_vite_manifest(
        '{"index.html":{"file":"assets/index.9f.js"}}', "https://x.com/.vite/manifest.json"))
    assert any(".js" in u for u in parse_next_build_manifest(
        'self.__BUILD_MANIFEST={"/":["static/chunks/pages/index-1.js"]}',
        "https://x.com/_next/static/x/_buildManifest.js"))


# ----------------------------------------------------------------------------
# SECTION: HTML script extraction + recursive JS-in-JS link discovery
# ----------------------------------------------------------------------------
_SCRIPT_SRC_RE = re.compile(r"<script[^>]+\bsrc\s*=\s*[\"']([^\"']+)[\"']", re.I)
_LINK_RE = re.compile(r"<link\b[^>]*>", re.I)
_HREF_RE = re.compile(r"\bhref\s*=\s*[\"']([^\"']+)[\"']", re.I)
_REL_RE = re.compile(r"\brel\s*=\s*[\"']([^\"']+)[\"']", re.I)
_AS_RE = re.compile(r"\bas\s*=\s*[\"']([^\"']+)[\"']", re.I)
_IMPORTMAP_RE = re.compile(
    r"<script[^>]+type\s*=\s*[\"']importmap[\"'][^>]*>(.*?)</script>", re.I | re.S)
_IMPORT_FROM_RE = re.compile(r"import\s+(?:[^'\"]+?\s+from\s+)?[\"']([^\"']+)[\"']", re.I)
_A_HREF_RE = re.compile(r"<a\b[^>]*\bhref\s*=\s*[\"']([^\"']+)[\"']", re.I)
_JS_STR_RE = re.compile(r"[\"']([^\"'\s]+\.m?js)(?:[\"'?#])")
_DYN_IMPORT_RE = re.compile(r"import\(\s*[\"']([^\"']+)[\"']\s*\)")


def extract_scripts_from_html(html: str, base: str) -> "set[str]":
    """Extract JS URLs from HTML: <script src>, module/preload links, importmap, imports."""
    out: "set[str]" = set()
    for m in _SCRIPT_SRC_RE.finditer(html):
        out.add(canonicalize_url(m.group(1), base))
    for tag in _LINK_RE.finditer(html):
        t = tag.group(0)
        hm = _HREF_RE.search(t)
        if not hm:
            continue
        hv = hm.group(1)
        rel = (_REL_RE.search(t).group(1).lower() if _REL_RE.search(t) else "")
        asv = (_AS_RE.search(t).group(1).lower() if _AS_RE.search(t) else "")
        if ("modulepreload" in rel
                or (("preload" in rel or "prefetch" in rel) and asv == "script")
                or looks_like_js_url(hv)):
            out.add(canonicalize_url(hv, base))
    for im in _IMPORTMAP_RE.finditer(html):
        try:
            data = json.loads(im.group(1))
            for v in (data.get("imports") or {}).values():
                if isinstance(v, str):
                    out.add(canonicalize_url(v, base))
            for scope in (data.get("scopes") or {}).values():
                if isinstance(scope, dict):
                    for v in scope.values():
                        if isinstance(v, str):
                            out.add(canonicalize_url(v, base))
        except Exception:
            pass
    for m in _IMPORT_FROM_RE.finditer(html):
        spec = m.group(1)
        if looks_like_js_url(spec) or spec.startswith((".", "/")):
            out.add(canonicalize_url(spec, base))
    return out


def extract_html_links(html: str, base: str) -> "set[str]":
    """Extract same-doc <a href> links for the crawl frontier."""
    out: "set[str]" = set()
    for m in _A_HREF_RE.finditer(html):
        h = m.group(1)
        if h.startswith(("javascript:", "mailto:", "tel:", "#", "data:")):
            continue
        out.add(canonicalize_url(h, base))
    return out


def extract_js_links(js_text: str, base: str) -> "set[str]":
    """Extract .js references and dynamic import() targets from inside a JS file."""
    out: "set[str]" = set()
    for m in _JS_STR_RE.finditer(js_text):
        out.add(canonicalize_url(m.group(1), base))
    for m in _DYN_IMPORT_RE.finditer(js_text):
        out.add(canonicalize_url(m.group(1), base))
    return out


@selftest("html.script_extraction")
def _t_html():
    html = ('<script src="/a.js"></script><link rel="modulepreload" href="/b.js">'
            '<script type="importmap">{"imports":{"x":"/c.js"}}</script><a href="/page2">')
    s = extract_scripts_from_html(html, "https://x.com/")
    assert {"https://x.com/a.js", "https://x.com/b.js", "https://x.com/c.js"} <= s, s
    assert "https://x.com/page2" in extract_html_links(html, "https://x.com/")


@selftest("jsinjs.links")
def _t_jsinjs():
    js = 'fetch("/api/x");var u="/static/lazy.js";import("/static/dyn.js")'
    s = extract_js_links(js, "https://x.com/app.js")
    assert "https://x.com/static/lazy.js" in s and "https://x.com/static/dyn.js" in s, s


# ----------------------------------------------------------------------------
# SECTION: Passive sources (historical/deleted JS + subdomains)
#   Pure parsers are unit-tested; async fetchers wrap engine + parser, guarded.
# ----------------------------------------------------------------------------
def parse_wayback_cdx(text: str) -> "set[str]":
    """Parse Wayback CDX output (JSON array or plain text lines) into all URLs.

    Returns every archived URL (not just .js); the orchestrator splits JS
    candidates from page seeds. Accepts both output=json and output=text.
    """
    out: "set[str]" = set()
    text = text.strip()
    if not text:
        return out
    if text[0] == "[":
        try:
            data = json.loads(text)
        except Exception:
            data = None
        if isinstance(data, list):
            for i, row in enumerate(data):
                if i == 0 and isinstance(row, list) and "original" in row:
                    continue
                url = row[0] if isinstance(row, list) and row else (
                    row if isinstance(row, str) else None)
                if url and "://" in url:
                    out.add(canonicalize_url(url))
            return out
    # plain-text: one original URL per line
    for line in text.splitlines():
        line = line.strip()
        if "://" in line:
            out.add(canonicalize_url(line.split()[0] if " " in line else line))
    return out


def parse_otx(text: str) -> "set[str]":
    """Parse AlienVault OTX url_list JSON into all URLs (pages + JS)."""
    out: "set[str]" = set()
    try:
        data = json.loads(text)
    except Exception:
        return out
    for item in (data.get("url_list") or []):
        u = item.get("url") if isinstance(item, dict) else None
        if u and "://" in u:
            out.add(canonicalize_url(u))
    return out


def parse_urlscan(text: str) -> "set[str]":
    """Parse URLScan.io search JSON into all URLs (page + task urls)."""
    out: "set[str]" = set()
    try:
        data = json.loads(text)
    except Exception:
        return out
    for r in (data.get("results") or []):
        if not isinstance(r, dict):
            continue
        for key in ("page", "task"):
            u = (r.get(key) or {}).get("url") if isinstance(r.get(key), dict) else None
            if u and "://" in u:
                out.add(canonicalize_url(u))
    return out


def parse_commoncrawl(text: str) -> "set[str]":
    """Parse Common Crawl index JSONL into all URLs."""
    out: "set[str]" = set()
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except Exception:
            continue
        u = obj.get("url") if isinstance(obj, dict) else None
        if u and "://" in u:
            out.add(canonicalize_url(u))
    return out


def parse_crtsh(text: str) -> "set[str]":
    """Parse crt.sh JSON into a set of hostnames (subdomains)."""
    out: "set[str]" = set()
    try:
        data = json.loads(text)
    except Exception:
        return out
    for row in (data if isinstance(data, list) else []):
        nv = row.get("name_value", "") if isinstance(row, dict) else ""
        for name in str(nv).split("\n"):
            name = name.strip().lstrip("*.").lower()
            if name and "." in name and " " not in name:
                out.add(name)
    return out


@dataclass
class SourceResult:
    urls: set
    status: str      # "ok" | "empty" | "http <code>" | "error: <msg>"
    detail: str = ""


def _prov_status(r: Response, n: int) -> "tuple[str, str]":
    if r.error:
        return f"error: {r.error}", r.error
    if r.status and r.status != 200:
        return f"http {r.status}", ""
    return ("ok" if n else "empty"), ""


async def _get_resilient(engine: HttpEngine, url: str, tries: int = 2) -> Response:
    """GET with a short retry on TRANSIENT failures (5xx, connection dropped).

    Archive services (web.archive.org, index.commoncrawl.org) frequently return
    503 or drop the connection under load; a brief backoff often succeeds.
    """
    r = None
    for i in range(tries):
        r = await engine.get(url)
        transient = (r.status and r.status >= 500) or (r.error and any(
            s in r.error.lower() for s in
            ("disconnect", "protocolerror", "connection reset", "remoteprotocol")))
        if not transient or i == tries - 1:
            return r
        await asyncio.sleep(1.5 * (i + 1))
    return r


async def source_wayback(engine: HttpEngine, domain: str) -> SourceResult:
    url = (f"http://web.archive.org/cdx/search/cdx?url={domain}/*"
           f"&output=text&fl=original&collapse=urlkey&limit=50000")
    r = await _get_resilient(engine, url)
    urls = parse_wayback_cdx(r.text) if (not r.error and r.text) else set()
    st, dt = _prov_status(r, len(urls))
    return SourceResult(urls, st, dt)


async def source_otx(engine: HttpEngine, domain: str) -> SourceResult:
    out: "set[str]" = set()
    last = None
    for page in (1, 2, 3, 4, 5):
        r = await engine.get(
            f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/url_list"
            f"?limit=500&page={page}")
        last = r
        if r.error or r.status != 200 or not r.text:
            break
        got = parse_otx(r.text)
        out |= got
        if len(got) < 500:
            break
    st, dt = _prov_status(last, len(out)) if last else ("empty", "")
    return SourceResult(out, "ok" if out else st, dt)


async def source_urlscan(engine: HttpEngine, domain: str) -> SourceResult:
    r = await engine.get(f"https://urlscan.io/api/v1/search/?q=domain:{domain}&size=1000")
    urls = parse_urlscan(r.text) if (not r.error and r.text) else set()
    st, dt = _prov_status(r, len(urls))
    return SourceResult(urls, st, dt)


async def source_commoncrawl(engine: HttpEngine, domain: str) -> SourceResult:
    r = await _get_resilient(engine, "https://index.commoncrawl.org/collinfo.json")
    if r.error or r.status != 200 or not r.text:
        st, dt = _prov_status(r, 0)
        return SourceResult(set(), st, dt)
    try:
        idx = json.loads(r.text)
    except Exception:
        return SourceResult(set(), "error: bad collinfo", "")
    if not idx or not isinstance(idx, list):
        return SourceResult(set(), "empty", "")
    api = idx[0].get("cdx-api")
    if not api:
        return SourceResult(set(), "empty", "")
    r2 = await _get_resilient(engine, f"{api}?url={domain}/*&output=json&fl=url&limit=50000")
    urls = parse_commoncrawl(r2.text) if (not r2.error and r2.text) else set()
    st, dt = _prov_status(r2, len(urls))
    return SourceResult(urls, st, dt)


async def source_crtsh(engine: HttpEngine, domain: str) -> SourceResult:
    r = None
    for attempt in range(2):  # crt.sh 5xx/rate-limits are common and transient
        r = await engine.get(f"https://crt.sh/?q=%25.{domain}&output=json")
        if not r.error and r.status == 200 and r.text.lstrip().startswith("["):
            hosts = parse_crtsh(r.text)
            return SourceResult(hosts, "ok" if hosts else "empty", "")
        if r.status and r.status >= 500 and attempt == 0:
            await asyncio.sleep(1.0)
            continue
        break
    st, dt = _prov_status(r, 0) if r else ("error: no response", "")
    return SourceResult(set(), st, dt)


@selftest("sources.parsers")
def _t_src():
    assert "https://x.com/a.js" in parse_wayback_cdx(
        '[["original"],["https://x.com/a.js"],["https://x.com/b.css"]]')
    assert "https://x.com/o.js" in parse_otx(
        '{"url_list":[{"url":"https://x.com/o.js"},{"url":"https://x.com/o.png"}]}')
    assert "https://x.com/u.js" in parse_urlscan(
        '{"results":[{"page":{"url":"https://x.com/u.js"}}]}')
    assert "https://x.com/c.js" in parse_commoncrawl(
        '{"url":"https://x.com/c.js"}\n{"url":"https://x.com/c.png"}')
    assert "cdn.x.com" in parse_crtsh('[{"name_value":"cdn.x.com\\nx.com"}]')
    assert "x.com" in parse_crtsh('[{"name_value":"*.x.com"}]')


@selftest("sources.harvest_pages_and_js")
def _t_src_pages():
    # providers now return ALL urls (pages + js) so pages can seed the crawler
    otx = parse_otx('{"url_list":[{"url":"https://x.com/buy/form"},{"url":"https://x.com/b.js"}]}')
    assert "https://x.com/buy/form" in otx and "https://x.com/b.js" in otx
    us = parse_urlscan(
        '{"results":[{"page":{"url":"https://x.com/p"},"task":{"url":"https://x.com/t"}}]}')
    assert {"https://x.com/p", "https://x.com/t"} <= us
    # wayback also accepts plain-text (output=text) responses
    wb = parse_wayback_cdx("https://x.com/a.js\nhttps://x.com/page")
    assert {"https://x.com/a.js", "https://x.com/page"} <= wb


# ----------------------------------------------------------------------------
# SECTION: Spider (active, level-batched concurrent depth-N crawl)
# ----------------------------------------------------------------------------
_ASSET_EXT_RE = re.compile(
    r"\.(css|png|jpe?g|gif|svg|webp|ico|woff2?|ttf|eot|pdf|zip|gz|mp4|webm|mp3|"
    r"js|mjs|cjs|json|xml|map|txt|wasm|avif)(\?|#|$)", re.I)


def _is_page(url: str) -> bool:
    """True if the URL looks like an HTML page (not a static asset)."""
    return not _ASSET_EXT_RE.search(urllib.parse.urlsplit(url).path)


class Spider:
    """Async, scope-guarded, level-batched HTML crawler."""

    def __init__(self, engine: HttpEngine, scope: Scope, cfg: Config):
        self.engine = engine
        self.scope = scope
        self.cfg = cfg
        self.host_stats: dict = {}   # host -> {"codes": {code: n}, "js": n}

    async def crawl(self, seeds: "list[str]"):
        js_urls: "set[str]" = set()
        html_records: "list[FileRecord]" = []
        visited: "set[str]" = set()
        frontier = [canonicalize_url(u) for u in seeds]
        pages = 0
        for depth in range(self.cfg.depth + 1):
            if not frontier or pages >= self.cfg.max_pages:
                break
            batch = []
            for u in frontier:
                if u in visited or not self.scope.in_scope(u):
                    continue
                visited.add(u)
                batch.append(u)
                if len(batch) + pages >= self.cfg.max_pages:
                    break
            if not batch:
                break
            results = await asyncio.gather(*[self.engine.get(u) for u in batch],
                                           return_exceptions=True)
            next_frontier: "list[str]" = []
            for u, r in zip(batch, results):
                host = _host(u)
                hs = self.host_stats.setdefault(host, {"codes": {}, "js": 0})
                if isinstance(r, Exception):
                    hs["codes"]["error"] = hs["codes"].get("error", 0) + 1
                    continue
                if r.error:
                    k = "timeout" if ("timeout" in r.error.lower() or "timed out" in r.error.lower()) else "error"
                    hs["codes"][k] = hs["codes"].get(k, 0) + 1
                    continue
                hs["codes"][str(r.status)] = hs["codes"].get(str(r.status), 0) + 1
                if r.status != 200:
                    continue
                pages += 1
                text = r.text or ""
                page_js = {j for j in extract_scripts_from_html(text, u) if self.scope.in_scope(j)}
                page_js |= {j for j in extract_js_links(text, u)
                            if looks_like_js_url(j) and self.scope.in_scope(j)}
                js_urls |= page_js
                hs["js"] += len(page_js)
                ctype = _header(r.headers, "content-type")
                if "html" in ctype.lower() or "<" in text[:200]:
                    body = r.content or text.encode("utf-8", "replace")
                    html_records.append(FileRecord(
                        u, {"crawl"}, r.status, ctype, len(body),
                        hashlib.sha256(body).hexdigest(), False, text))
                    if depth < self.cfg.depth:
                        for link in extract_html_links(text, u):
                            if (link not in visited and self.scope.in_scope(link)
                                    and _is_page(link)):
                                next_frontier.append(link)
            frontier = next_frontier
        return js_urls, html_records


@selftest("spider.depth_crawl")
def _t_spider():
    base, stop = _serve({
        "/": ("text/html", b'<script src="/app.js"></script><a href="/page2">go</a>'),
        "/page2": ("text/html", b'<script src="/admin.js"></script>'),
        "/app.js": ("application/javascript", b"1"),
        "/admin.js": ("application/javascript", b"2"),
    })

    async def go():
        sc = Scope(_host(base), allow_subs=True)
        sp = Spider(HttpEngine(Config.defaults()), sc, Config.defaults())
        js, _ = await sp.crawl([base + "/"])
        await sp.engine.close()
        return js

    try:
        js = _run(go())
        assert any(u.endswith("/app.js") for u in js), js
        assert any(u.endswith("/admin.js") for u in js), js  # found only via depth-1 crawl
    finally:
        stop()


# ----------------------------------------------------------------------------
# SECTION: Analysis - secrets, endpoints, entropy, JWT, juice score
# ----------------------------------------------------------------------------
@dataclass
class Secret:
    type: str
    match: str
    entropy: float
    severity: str


# (name, compiled regex capturing the token in group(1), severity)
_SECRET_PATTERNS = [
    ("aws_access_key_id", re.compile(r"\b(AKIA[0-9A-Z]{16})\b"), "high"),
    ("aws_sts_key", re.compile(r"\b(ASIA[0-9A-Z]{16})\b"), "high"),
    ("gcp_api_key", re.compile(r"\b(AIza[0-9A-Za-z\-_]{35})\b"), "medium"),
    ("stripe_secret_key", re.compile(r"\b(sk_live_[0-9a-zA-Z]{24,})"), "critical"),
    ("stripe_restricted_key", re.compile(r"\b(rk_live_[0-9a-zA-Z]{24,})"), "high"),
    ("github_pat", re.compile(r"\b(ghp_[A-Za-z0-9]{36})\b"), "high"),
    ("github_fine_grained_pat", re.compile(r"\b(github_pat_[A-Za-z0-9_]{82})\b"), "high"),
    ("github_oauth", re.compile(r"\b(gh[ousr]_[A-Za-z0-9]{36})\b"), "high"),
    ("gitlab_pat", re.compile(r"\b(glpat-[A-Za-z0-9\-_]{20})\b"), "high"),
    ("slack_token", re.compile(r"\b(xox[abprs]-[0-9A-Za-z-]{10,})"), "high"),
    ("slack_webhook", re.compile(
        r"(https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+)"), "high"),
    ("discord_webhook", re.compile(
        r"(https://discord(?:app)?\.com/api/webhooks/[0-9]+/[A-Za-z0-9_\-]+)"), "medium"),
    ("google_oauth_refresh", re.compile(r"\b(1//0[A-Za-z0-9\-_]{40,})"), "high"),
    ("twilio_account_sid", re.compile(r"\b(AC[a-f0-9]{32})\b"), "medium"),
    ("sendgrid_key", re.compile(r"\b(SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43})\b"), "high"),
    ("mailgun_key", re.compile(r"\b(key-[a-f0-9]{32})\b"), "medium"),
    ("npm_token", re.compile(r"\b(npm_[A-Za-z0-9]{36})\b"), "high"),
    ("square_token", re.compile(r"\b(EAAA[A-Za-z0-9\-_]{60,})"), "high"),
    ("paypal_token", re.compile(r"(access_token\$production\$[A-Za-z0-9]+\$[a-f0-9]+)"), "high"),
    ("openai_key", re.compile(r"\b(sk-(?:proj-)?[A-Za-z0-9]{20,})"), "high"),
    ("anthropic_key", re.compile(r"\b(sk-ant-[A-Za-z0-9_\-]{20,})"), "high"),
    ("huggingface_token", re.compile(r"\b(hf_[A-Za-z0-9]{30,})"), "high"),
    ("digitalocean_token", re.compile(r"\b(dop_v1_[a-f0-9]{64})\b"), "high"),
    ("mapbox_secret", re.compile(r"\b(sk\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+)"), "high"),
    ("azure_storage_conn", re.compile(
        r"(DefaultEndpointsProtocol=https?;AccountName=[^;]+;AccountKey=[A-Za-z0-9+/=]{20,})"),
     "critical"),
    ("private_key", re.compile(
        r"(-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY-----)"), "critical"),
    ("jwt", re.compile(r"\b(eyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]*)"), "medium"),
    ("mongodb_uri", re.compile(r"(mongodb(?:\+srv)?://[^\s\"'<>]+)"), "high"),
    ("postgres_uri", re.compile(
        r"(postgres(?:ql)?://[^\s\"'<>:]+:[^\s\"'<>@]+@[^\s\"'<>]+)"), "high"),
    ("mysql_uri", re.compile(r"(mysql://[^\s\"'<>:]+:[^\s\"'<>@]+@[^\s\"'<>]+)"), "high"),
    ("redis_uri", re.compile(r"(redis://[^\s\"'<>:]*:[^\s\"'<>@]+@[^\s\"'<>]+)"), "medium"),
    ("amqp_uri", re.compile(r"(amqp://[^\s\"'<>:]+:[^\s\"'<>@]+@[^\s\"'<>]+)"), "medium"),
    ("basic_auth_header", re.compile(r"(Authorization:\s*Basic\s+[A-Za-z0-9+/=]{8,})"), "medium"),
    ("bearer_token", re.compile(r"(Authorization:\s*Bearer\s+[A-Za-z0-9._\-]{12,})"), "medium"),
    ("firebase_endpoint", re.compile(r"([a-z0-9\-]+\.firebaseio\.com)"), "low"),
    ("google_service_account", re.compile(r'("type"\s*:\s*"service_account")'), "high"),
]

_GENERIC_SECRET_RE = re.compile(
    r"(?i)\b(api[_-]?key|secret|token|password|passwd|client[_-]?secret|access[_-]?key|"
    r"auth[_-]?token|private[_-]?key|signing[_-]?key|jwt[_-]?secret|app[_-]?secret|"
    r"webhook[_-]?secret|cookie[_-]?secret)\b\s*[:=]\s*[\"']([^\"']{8,})[\"']")

_PLACEHOLDER_RE = re.compile(
    r"(?i)(your[_-]?|changeme|placeholder|example|xxxx+|<[^>]+>|\.\.\.|"
    r"test[_-]?key|dummy|sample|redacted|insert[_-]?here|process\.env)")

_ABS_URL_RE = re.compile(r"https?://[A-Za-z0-9.\-]+(?:/[A-Za-z0-9_\-./?=&%~+]*)?")
_QUOTED_PATH_RE = re.compile(r"[\"'`](/[A-Za-z0-9_][A-Za-z0-9_\-/.]{1,})[\"'`?#]")


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    freq: dict = {}
    for ch in s:
        freq[ch] = freq.get(ch, 0) + 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in freq.values())


def decode_jwt(tok: str) -> "Optional[dict]":
    """Decode a JWT's header + payload (no signature verification)."""
    try:
        parts = tok.split(".")
        if len(parts) < 2:
            return None

        def b64(seg: str):
            seg += "=" * (-len(seg) % 4)
            return json.loads(base64.urlsafe_b64decode(seg).decode("utf-8", "replace"))

        return {"header": b64(parts[0]), "payload": b64(parts[1])}
    except Exception:
        return None


def scan_secrets(text: str) -> "list[Secret]":
    """Extract secrets: prefixed high-confidence patterns + entropy-gated generics."""
    found: "list[Secret]" = []
    seen: set = set()
    for name, rx, sev in _SECRET_PATTERNS:
        for m in rx.finditer(text):
            val = m.group(1)
            key = (name, val)
            if key in seen:
                continue
            seen.add(key)
            found.append(Secret(name, val[:160], round(shannon_entropy(val), 2), sev))
    for m in _GENERIC_SECRET_RE.finditer(text):
        val = m.group(2)
        if _PLACEHOLDER_RE.search(val):
            continue
        ent = shannon_entropy(val)
        if ent < 3.5:
            continue
        key = ("generic_secret", val)
        if key in seen:
            continue
        seen.add(key)
        found.append(Secret("generic_secret", val[:160], round(ent, 2), "medium"))
    return found


def scan_endpoints(text: str) -> "list[str]":
    """LinkFinder-style extraction of absolute URLs + quoted paths."""
    out: "list[str]" = []
    seen: set = set()
    for m in _ABS_URL_RE.finditer(text):
        p = m.group(0).rstrip("\\\"'")
        if p not in seen:
            seen.add(p)
            out.append(p)
    for m in _QUOTED_PATH_RE.finditer(text):
        p = m.group(1)
        if p not in seen:
            seen.add(p)
            out.append(p)
    return out[:2000]


_ADMIN_ENDPOINT_RE = re.compile(
    r"admin|internal|debug|actuator|management|_next|graphql|billing|payment|"
    r"secret|token|export|upload", re.I)


def score_record(rec: FileRecord, secrets: "list[Secret]", endpoints: "list[str]") -> float:
    """Compute a juice score used to rank which file to read first."""
    sev_w = {"critical": 40.0, "high": 25.0, "medium": 12.0, "low": 4.0}
    score = 0.0
    for s in secrets:
        score += sev_w.get(s.severity, 8.0)
    score += 3.0 * sum(1 for e in endpoints if _ADMIN_ENDPOINT_RE.search(e))
    score += 0.1 * len(endpoints)
    if rec.revealed_sources:
        score += 5.0
    if rec.sourcemap_url:
        score += 3.0
    if rec.bytes and rec.bytes < 2000:
        score += 1.0
    if re.search(r"admin|config|env|secret|internal|debug", rec.url, re.I):
        score += 5.0
    return round(score, 2)


@selftest("analyze.secrets_endpoints_score")
def _t_an():
    txt = ('AKIAIOSFODNN7EXAMPLE k="sk_live_' + "a" * 24 + '" '
           'url="/api/v1/admin" x="lowentropydecoy"')
    types = {s.type for s in scan_secrets(txt)}
    assert "aws_access_key_id" in types, types
    assert any("stripe" in t for t in types), types
    assert "/api/v1/admin" in scan_endpoints(txt)
    assert shannon_entropy("aaaaaaaa") < shannon_entropy("aB3$xY9!zQ")
    hi = score_record(FileRecord("u", set(), 200, "application/javascript", 100, "h", True, txt),
                      scan_secrets(txt), scan_endpoints(txt))
    lo = score_record(FileRecord("u2", set(), 200, "application/javascript", 100, "h2", True, "benign"),
                      [], [])
    assert hi > lo, (hi, lo)


@selftest("analyze.jwt_decode")
def _t_jwt():
    # {"alg":"none"} . {"role":"admin"}
    h = base64.urlsafe_b64encode(b'{"alg":"none"}').decode().rstrip("=")
    p = base64.urlsafe_b64encode(b'{"role":"admin"}').decode().rstrip("=")
    dec = decode_jwt(f"{h}.{p}.")
    assert dec and dec["payload"]["role"] == "admin" and dec["header"]["alg"] == "none"


# ----------------------------------------------------------------------------
# SECTION: validate.live (opt-in) - prove secrets with read-only calls
# ----------------------------------------------------------------------------
def _hmac_sha256(key: bytes, msg: str) -> bytes:
    return hmac.new(key, msg.encode("utf-8"), hashlib.sha256).digest()


def derive_signing_key(secret_key: str, date_stamp: str, region: str, service: str) -> bytes:
    """AWS SigV4 signing key derivation (deterministic; matches AWS doc vector)."""
    k_date = _hmac_sha256(("AWS4" + secret_key).encode("utf-8"), date_stamp)
    k_region = _hmac_sha256(k_date, region)
    k_service = _hmac_sha256(k_region, service)
    return _hmac_sha256(k_service, "aws4_request")


def build_sts_request(akid: str, secret: str, session_token: "Optional[str]" = None,
                      region: str = "us-east-1") -> "tuple[str, dict]":
    """Build a signed STS GetCallerIdentity GET request (url, headers)."""
    service, host = "sts", "sts.amazonaws.com"
    t = time.gmtime()
    amzdate = time.strftime("%Y%m%dT%H%M%SZ", t)
    datestamp = time.strftime("%Y%m%d", t)
    method, canonical_uri = "GET", "/"
    qs = "Action=GetCallerIdentity&Version=2011-06-15"
    payload_hash = hashlib.sha256(b"").hexdigest()
    if session_token:
        canonical_headers = (f"host:{host}\nx-amz-date:{amzdate}\n"
                             f"x-amz-security-token:{session_token}\n")
        signed_headers = "host;x-amz-date;x-amz-security-token"
    else:
        canonical_headers = f"host:{host}\nx-amz-date:{amzdate}\n"
        signed_headers = "host;x-amz-date"
    canonical_request = "\n".join(
        [method, canonical_uri, qs, canonical_headers, signed_headers, payload_hash])
    scope = f"{datestamp}/{region}/{service}/aws4_request"
    string_to_sign = "\n".join(
        ["AWS4-HMAC-SHA256", amzdate, scope,
         hashlib.sha256(canonical_request.encode()).hexdigest()])
    signing_key = derive_signing_key(secret, datestamp, region, service)
    signature = hmac.new(signing_key, string_to_sign.encode(), hashlib.sha256).hexdigest()
    auth = (f"AWS4-HMAC-SHA256 Credential={akid}/{scope}, "
            f"SignedHeaders={signed_headers}, Signature={signature}")
    headers = {"x-amz-date": amzdate, "Authorization": auth}
    if session_token:
        headers["x-amz-security-token"] = session_token
    return f"https://{host}/?{qs}", headers


def _simple_http(method: str, url: str, headers=None, timeout=15.0, proxy=None):
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    hs = [urllib.request.HTTPSHandler(context=ctx)]
    if proxy:
        hs.append(urllib.request.ProxyHandler({"http": proxy, "https": proxy}))
    opener = urllib.request.build_opener(*hs)
    req = urllib.request.Request(url, method=method, headers=headers or {})
    try:
        with opener.open(req, timeout=timeout) as r:
            return getattr(r, "status", 200), r.read().decode("utf-8", "replace")[:2000]
    except urllib.error.HTTPError as e:
        try:
            body = e.read().decode("utf-8", "replace")[:2000]
        except Exception:
            body = ""
        return e.code, body
    except Exception as e:  # noqa: BLE001
        return None, f"{type(e).__name__}: {e}"


async def _aget(url, headers=None, timeout=15.0, proxy=None, method="GET"):
    return await asyncio.to_thread(_simple_http, method, url, headers, timeout, proxy)


async def validate_secret(engine: "Optional[HttpEngine]", secret: Secret) -> dict:
    """Actively validate a secret with a READ-ONLY call. Never destructive."""
    t, v = secret.type, secret.match
    proxy = engine.cfg.proxy if engine else None
    timeout = engine.cfg.timeout if engine else 15.0

    def result(status, detail=""):
        return {"type": t, "match": v[:40] + ("..." if len(v) > 40 else ""),
                "status": status, "detail": detail}

    try:
        if t == "jwt":
            dec = decode_jwt(v)
            return result("decoded" if dec else "unverified", dec or "")
        if t == "private_key":
            return result("found", "private key material present (no network check)")
        if t in ("mongodb_uri", "postgres_uri", "mysql_uri", "redis_uri", "amqp_uri"):
            return result("unverified", "DB URI - not connecting (would be intrusive)")

        if t in ("stripe_secret_key", "stripe_restricted_key"):
            b = base64.b64encode((v + ":").encode()).decode()
            st, body = await _aget("https://api.stripe.com/v1/account",
                                   {"Authorization": "Basic " + b}, timeout, proxy)
            return result("valid" if st == 200 else "invalid", f"HTTP {st}")
        if t in ("github_pat", "github_fine_grained_pat", "github_oauth"):
            st, body = await _aget("https://api.github.com/user",
                                   {"Authorization": "token " + v,
                                    "User-Agent": "godjs"}, timeout, proxy)
            return result("valid" if st == 200 else "invalid", f"HTTP {st}")
        if t == "openai_key":
            st, _ = await _aget("https://api.openai.com/v1/models",
                                {"Authorization": "Bearer " + v}, timeout, proxy)
            return result("valid" if st == 200 else "invalid", f"HTTP {st}")
        if t == "huggingface_token":
            st, _ = await _aget("https://huggingface.co/api/whoami-v2",
                                {"Authorization": "Bearer " + v}, timeout, proxy)
            return result("valid" if st == 200 else "invalid", f"HTTP {st}")
        if t == "npm_token":
            st, _ = await _aget("https://registry.npmjs.org/-/whoami",
                                {"Authorization": "Bearer " + v}, timeout, proxy)
            return result("valid" if st == 200 else "invalid", f"HTTP {st}")
        if t == "gcp_api_key":
            st, body = await _aget(
                "https://maps.googleapis.com/maps/api/geocode/json?address=x&key=" + v,
                None, timeout, proxy)
            ok = st == 200 and "REQUEST_DENIED" not in (body or "")
            return result("valid" if ok else "invalid", f"HTTP {st}")
        if t == "slack_webhook":
            # GET (never POST) - valid hooks reject the payload, dead ones say no_service
            st, body = await _aget(v, None, timeout, proxy)
            if body and "no_service" in body:
                return result("invalid", "no_service")
            if st in (400, 405) or (body and "invalid_payload" in body):
                return result("valid", f"HTTP {st} (endpoint live)")
            return result("unverified", f"HTTP {st}")
        if t == "aws_access_key_id":
            return result("unverified", "need paired secret key to sign STS call")
    except Exception as e:  # noqa: BLE001
        return result("unverified", f"{type(e).__name__}: {e}")
    return result("unverified", "no validator for this type")


@selftest("validate.sigv4_vector")
def _t_sig():
    # Authoritative AWS "Deriving the signing key" doc example.
    k = derive_signing_key(
        "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY", "20150830", "us-east-1", "iam")
    assert k.hex() == "c4afb1cc5771d871763a393e44b703571b55cc28424d1a5e86da6ed3c154a4b9", k.hex()


@selftest("validate.offline_dispatch")
def _t_valoff():
    h = base64.urlsafe_b64encode(b'{"alg":"none"}').decode().rstrip("=")
    p = base64.urlsafe_b64encode(b'{"sub":"1"}').decode().rstrip("=")
    r1 = _run(validate_secret(None, Secret("jwt", f"{h}.{p}.", 0.0, "medium")))
    assert r1["status"] == "decoded", r1
    r2 = _run(validate_secret(None, Secret("private_key", "-----BEGIN PRIVATE KEY-----", 0.0, "critical")))
    assert r2["status"] == "found", r2
    r3 = _run(validate_secret(None, Secret("mongodb_uri", "mongodb://a:b@h/db", 0.0, "high")))
    assert r3["status"] == "unverified", r3


# ----------------------------------------------------------------------------
# SECTION: Reporters (js_urls.txt, results.json, self-contained report.html)
# ----------------------------------------------------------------------------
@dataclass
class RunState:
    domain: str
    records: "list[FileRecord]"
    coverage: dict
    findings: dict
    json_only: bool = False


def _esc(s: str) -> str:
    return (str(s).replace("&", "&amp;").replace("<", "&lt;")
            .replace(">", "&gt;").replace('"', "&quot;"))


def _record_to_dict(r: FileRecord) -> dict:
    d = asdict(r)
    d["sources"] = sorted(r.sources) if isinstance(r.sources, set) else list(r.sources or [])
    d.pop("text", None)  # never dump full file bodies into the report
    return d


def write_urls_txt(records: "list[FileRecord]", path) -> None:
    urls = sorted({r.url for r in records})
    Path(path).write_text("\n".join(urls) + ("\n" if urls else ""), encoding="utf-8")


def write_results_json(state: RunState, path) -> None:
    recs = sorted(state.records, key=lambda r: (-r.score, r.url))
    data = {
        "domain": state.domain,
        "coverage": state.coverage,
        "findings": state.findings,
        "count": len(recs),
        "records": [_record_to_dict(r) for r in recs],
    }
    Path(path).write_text(json.dumps(data, indent=2, default=str), encoding="utf-8")


_SEV_COLOR = {"critical": "#e5484d", "high": "#f76808", "medium": "#ffb224",
              "low": "#8f8f8f", "decoded": "#3e63dd", "valid": "#e5484d",
              "invalid": "#4c9a4c", "found": "#e5484d", "unverified": "#8f8f8f"}


def render_html(state: RunState) -> str:
    recs = sorted(state.records, key=lambda r: (-r.score, r.url))
    total = len(recs)
    with_secrets = sum(1 for r in recs if r.secrets)
    cov = state.coverage or {}
    rows = []
    for r in recs:
        sev_chips = "".join(
            f'<span class="chip" style="background:{_SEV_COLOR.get(s.get("severity","low") if isinstance(s,dict) else getattr(s,"severity","low"),"#8f8f8f")}">'
            f'{_esc(s.get("type") if isinstance(s,dict) else getattr(s,"type",""))}</span>'
            for s in (r.secrets or []))
        secret_detail = "".join(
            f"<div class='mono'>{_esc((s.get('type') if isinstance(s,dict) else getattr(s,'type','')))}: "
            f"{_esc((s.get('match') if isinstance(s,dict) else getattr(s,'match','')))}</div>"
            for s in (r.secrets or []))
        ep_detail = "".join(f"<div class='mono'>{_esc(e)}</div>" for e in (r.endpoints or [])[:60])
        rev_detail = "".join(f"<div class='mono'>{_esc(p)}</div>" for p in (r.revealed_sources or [])[:60])
        val_detail = "".join(
            f"<div class='mono'>{_esc(v.get('type'))} = <b style='color:{_SEV_COLOR.get(v.get('status'),'#8f8f8f')}'>"
            f"{_esc(v.get('status'))}</b> ({_esc(v.get('detail'))})</div>"
            for v in (r.validated or []))
        details = ""
        if secret_detail or ep_detail or rev_detail or val_detail:
            details = (f"<tr class='detail'><td colspan='6'>"
                       f"{'<h4>Secrets</h4>'+secret_detail if secret_detail else ''}"
                       f"{'<h4>Validation</h4>'+val_detail if val_detail else ''}"
                       f"{'<h4>Revealed sources</h4>'+rev_detail if rev_detail else ''}"
                       f"{'<h4>Endpoints</h4>'+ep_detail if ep_detail else ''}"
                       f"</td></tr>")
        sm = "map" if r.sourcemap_url else ""
        rows.append(
            f"<tr><td class='score'>{r.score:g}</td>"
            f"<td class='url'><a href='{_esc(r.url)}' target='_blank' rel='noopener'>{_esc(r.url)}</a><br>{sev_chips}</td>"
            f"<td>{r.bytes or 0}</td><td>{_esc(','.join(sorted(r.sources)) if isinstance(r.sources,set) else '')}</td>"
            f"<td>{len(r.endpoints or [])}</td><td>{sm}</td></tr>{details}")
    cov_items = "".join(f"<li><b>{_esc(k)}</b>: {_esc(v)}</li>" for k, v in cov.items())
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>GodJsGlitch report - {_esc(state.domain)}</title>
<style>
:root{{color-scheme:light dark}}
body{{font-family:system-ui,Segoe UI,Roboto,sans-serif;margin:0;background:#0d0d10;color:#e8e8ea}}
header{{padding:20px 24px;background:#15151a;border-bottom:1px solid #2a2a33}}
h1{{margin:0;font-size:20px}} .sub{{color:#9a9aa5;font-size:13px;margin-top:4px}}
.wrap{{padding:20px 24px}}
.stats{{display:flex;gap:16px;flex-wrap:wrap;margin-bottom:16px}}
.stat{{background:#15151a;border:1px solid #2a2a33;border-radius:10px;padding:12px 16px;min-width:120px}}
.stat b{{font-size:22px;display:block}}
ul.cov{{list-style:none;padding:0;margin:0;columns:2;font-size:13px;color:#c7c7cf}}
table{{width:100%;border-collapse:collapse;font-size:13px}}
th,td{{text-align:left;padding:8px 10px;border-bottom:1px solid #23232b;vertical-align:top}}
th{{position:sticky;top:0;background:#15151a;color:#9a9aa5;font-weight:600}}
td.score{{font-weight:700;color:#ffb224}} td.url{{word-break:break-all;max-width:640px}}
a{{color:#7aa2ff;text-decoration:none}}
.chip{{display:inline-block;color:#111;font-size:10px;font-weight:700;padding:1px 6px;border-radius:6px;margin:2px 3px 0 0}}
.mono{{font-family:ui-monospace,Menlo,Consolas,monospace;font-size:12px;color:#c7c7cf;word-break:break-all}}
tr.detail td{{background:#101015;border-bottom:2px solid #23232b}}
h4{{margin:10px 0 4px;font-size:12px;color:#9a9aa5;text-transform:uppercase;letter-spacing:.5px}}
.tablewrap{{overflow-x:auto}}
@media (prefers-color-scheme:light){{body{{background:#fff;color:#111}}header,.stat,th{{background:#f6f6f8}}header{{border-color:#e3e3e8}}}}
</style></head>
<body>
<header><h1>GodJsGlitch &mdash; {_esc(state.domain)}</h1>
<div class="sub">{total} unique JS files &middot; {with_secrets} with secret candidates &middot; ranked by juice score</div></header>
<div class="wrap">
<div class="stats">
<div class="stat"><b>{total}</b>JS files</div>
<div class="stat"><b>{with_secrets}</b>with secrets</div>
<div class="stat"><b>{sum(len(r.endpoints or []) for r in recs)}</b>endpoints</div>
<div class="stat"><b>{sum(1 for r in recs if r.sourcemap_url)}</b>source maps</div>
</div>
<h4>Coverage</h4><ul class="cov">{cov_items}</ul>
<div class="tablewrap"><table>
<thead><tr><th>Score</th><th>URL / secrets</th><th>Bytes</th><th>Source</th><th>Endpoints</th><th>Map</th></tr></thead>
<tbody>{''.join(rows)}</tbody>
</table></div>
</div></body></html>"""


def write_all(state: RunState, outdir) -> None:
    out = Path(outdir)
    out.mkdir(parents=True, exist_ok=True)
    write_urls_txt(state.records, out / "js_urls.txt")
    write_results_json(state, out / "results.json")
    if not state.json_only:
        (out / "report.html").write_text(render_html(state), encoding="utf-8")


@selftest("report.writers")
def _t_rep():
    import tempfile
    recs = [
        FileRecord("https://x.com/b.js", {"crawl"}, 200, "application/javascript", 10, "h1", True, ""),
        FileRecord("https://x.com/a.js", {"wayback"}, 200, "application/javascript", 10, "h2", True, ""),
    ]
    d = tempfile.mkdtemp()
    st = RunState("x.com", recs, {"total": 2}, {})
    write_all(st, d)
    lines = Path(d, "js_urls.txt").read_text().split()
    assert lines == sorted(lines) and len(lines) == 2, lines
    j = json.loads(Path(d, "results.json").read_text())
    assert j["coverage"]["total"] == 2 and j["count"] == 2
    html = render_html(st)
    assert "<html" in html.lower() and "x.com" in html


# ----------------------------------------------------------------------------
# SECTION: Bridge - opportunistically use Go tools if present (never required)
# ----------------------------------------------------------------------------
def tool_on_path(name: str) -> bool:
    return shutil.which(name) is not None


def parse_tool_lines(text: str) -> "set[str]":
    """Parse newline-delimited URLs emitted by katana/gau/etc."""
    out: "set[str]" = set()
    for line in (text or "").splitlines():
        line = line.strip()
        if line and "://" in line:
            out.add(canonicalize_url(line))
    return out


def parse_host_lines(text: str) -> "set[str]":
    """Parse newline-delimited hostnames emitted by subfinder/etc."""
    out: "set[str]" = set()
    for line in (text or "").splitlines():
        line = line.strip().lower()
        if not line:
            continue
        if "://" in line:
            line = urllib.parse.urlsplit(line).hostname or ""
        line = line.split("/")[0].strip().lstrip("*.")
        if line and "." in line and " " not in line:
            out.add(line)
    return out


async def _run_tool(args: "list[str]", timeout: float = 120.0) -> str:
    try:
        proc = await asyncio.create_subprocess_exec(
            *args, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL)
        out, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        return out.decode("utf-8", "replace")
    except Exception:
        try:
            proc.kill()
        except Exception:
            pass
        return ""


async def bridge_augment(domain: str, scope: Scope) -> "set[str]":
    """Augment discovery with any Go tools on PATH. Returns extra in-scope JS URLs."""
    out: "set[str]" = set()
    tasks = []
    if tool_on_path("gau"):
        tasks.append(_run_tool(["gau", domain]))
    if tool_on_path("waybackurls"):
        tasks.append(_run_tool(["waybackurls", domain]))
    if tool_on_path("katana"):
        tasks.append(_run_tool(
            ["katana", "-u", f"https://{domain}", "-jc", "-silent", "-d", "2"]))
    results = await asyncio.gather(*tasks) if tasks else []
    for txt in results:
        for u in parse_tool_lines(txt):
            if looks_like_js_url(u) and scope.in_scope(u):
                out.add(u)
    return out


async def bridge_subdomains(domain: str, scope: Scope) -> "set[str]":
    """Enumerate subdomains via subfinder if present. Returns in-scope hostnames."""
    if not tool_on_path("subfinder"):
        return set()
    txt = await _run_tool(["subfinder", "-d", domain, "-silent"])
    return {h for h in parse_host_lines(txt) if scope.in_scope("https://" + h + "/")}


@selftest("bridge.parse_and_absent")
def _t_bridge():
    assert parse_tool_lines("https://x.com/a.js\n\nhttps://x.com/b.js\n") == {
        "https://x.com/a.js", "https://x.com/b.js"}
    # this machine has no Go tools -> augment returns empty and never raises
    assert _run(bridge_augment("example.com", Scope("example.com"))) == set()


@selftest("bridge.subfinder_parse_and_absent")
def _t_bridge_sf():
    hosts = parse_host_lines("www.x.com\napi.x.com\n\nhttps://cdn.x.com/\n*.x.com\n")
    assert {"www.x.com", "api.x.com", "cdn.x.com", "x.com"} <= hosts
    # subfinder absent on this machine -> empty, never raises
    assert _run(bridge_subdomains("example.com", Scope("example.com"))) == set()


# ----------------------------------------------------------------------------
# SECTION: Orchestrator - recursive fixpoint discovery pipeline
# ----------------------------------------------------------------------------
def _vlog(cfg: Config, msg: str) -> None:
    """Print a diagnostic line when --verbose is on."""
    if getattr(cfg, "verbose", 0):
        print(f"[godjsglitch]   {msg}", file=sys.stderr)


def _host_summary(hs: dict) -> str:
    """One-line outcome for a crawled host: '200 (N js)' / '403' / 'timeout' / ..."""
    codes = hs.get("codes", {})
    if "200" in codes:
        return f"200 ({hs.get('js', 0)} js)"
    for pref in ("403", "401", "429", "503", "500", "302", "301"):
        if pref in codes:
            return pref
    if "timeout" in codes:
        return "timeout"
    if "error" in codes:
        return "error/unreachable"
    return ",".join(sorted(codes)) or "no-response"


async def render_pages(cfg: Config, scope: Scope, seeds: "list[str]") -> "tuple[set, str]":
    """Drive headless Chromium (Playwright) to capture runtime-loaded JS.

    Returns (js_urls, status). This is the only path that executes JavaScript,
    so it captures dynamically-injected / lazily-loaded scripts exactly as the
    browser's Network tab would - beyond what static parsing can see.
    """
    if not HAVE_PLAYWRIGHT:
        return set(), "playwright not installed"
    js: "set[str]" = set()
    launch_kw: dict = {"headless": True}
    if cfg.proxy:
        launch_kw["proxy"] = {"server": cfg.proxy}
    try:
        async with async_playwright() as p:
            browser = await p.chromium.launch(**launch_kw)
            ctx = await browser.new_context(
                user_agent=cfg.ua, ignore_https_errors=True,
                extra_http_headers=dict(cfg.headers or {}))
            for url in list(seeds)[:cfg.render_pages]:
                page = await ctx.new_page()
                collected: "set[str]" = set()

                def on_resp(resp, _c=collected):
                    try:
                        rt = resp.request.resource_type
                    except Exception:
                        rt = ""
                    u = resp.url
                    if rt == "script" or looks_like_js_url(u):
                        _c.add(u.split("#")[0])

                page.on("response", on_resp)
                try:
                    await page.goto(url, wait_until="networkidle",
                                    timeout=int(cfg.timeout * 1000))
                    try:
                        await page.evaluate("window.scrollTo(0, document.body.scrollHeight)")
                    except Exception:
                        pass
                    await page.wait_for_timeout(1200)
                except Exception:
                    pass
                js |= collected
                await page.close()
            await browser.close()
    except Exception as e:  # noqa: BLE001
        msg = str(e).lower()
        if "node" in msg or "no such file" in msg:
            return js, ("error: Playwright driver needs Node.js. Cleanest fix - use a venv "
                        "with pip (bundles its own node): python3 -m venv ~/.venv/godjs && "
                        "source ~/.venv/godjs/bin/activate && pip install playwright httpx && "
                        "playwright install chromium. (Or, for apt's python3-playwright: "
                        "sudo apt install nodejs)")
        if "executable doesn't exist" in msg or "playwright install" in msg:
            return js, "error: browser not installed - run: playwright install chromium"
        return js, f"error: {type(e).__name__}: {e}"
    return js, "ok"


def _is_local_host(host: str) -> bool:
    host = (host or "").lower()
    if host in ("localhost", "127.0.0.1", "::1"):
        return True
    if _IP_RE.match(host):
        return (host.startswith(("127.", "10.", "192.168.", "169.254."))
                or host.startswith("172."))
    return False


def _safe_child_path(root: Path, rel: str) -> Path:
    """Resolve rel under root, refusing traversal outside root."""
    rel = rel.replace("webpack://", "").lstrip("/")
    parts = [p for p in re.split(r"[\\/]+", rel) if p not in ("", ".", "..")]
    target = (root / "/".join(parts)).resolve()
    if not str(target).startswith(str(root.resolve())):
        return root / (hashlib.sha1(rel.encode()).hexdigest() + ".txt")
    return target


class Orchestrator:
    """Wires all techniques into one recursive, scope-guarded, capped pipeline."""

    def __init__(self, cfg: Config):
        self.cfg = cfg

    def _build_scope(self) -> Scope:
        cfg = self.cfg
        allow_hosts: set = set()
        if cfg.scope_file and Path(cfg.scope_file).exists():
            for line in Path(cfg.scope_file).read_text(encoding="utf-8", errors="replace").splitlines():
                line = line.strip()
                if line and not line.startswith("#"):
                    allow_hosts.add(line)
        return Scope(cfg.domain, allow_subs=cfg.allow_subs, allow_hosts=allow_hosts)

    async def run(self) -> RunState:
        cfg = self.cfg
        scope = self._build_scope()
        engine = HttpEngine(cfg)
        prober = Prober(engine)
        coverage: dict = {"providers": {}, "techniques": {}}
        candidates: "set[str]" = set()
        subdomains: "set[str]" = set()
        local = _is_local_host(apex_of(cfg.domain))

        # --- 1. Passive archives (skipped for local/IP targets) ---
        # All providers run concurrently under one wall-clock budget: a slow or
        # hanging provider can never stall the run - we take whatever finished.
        # Providers return ALL urls; JS becomes a candidate, pages become crawl seeds.
        # pre-seeded JS candidates (e.g. from an apex-level archive sweep in --per-host mode)
        candidates |= {u for u in (cfg.extra_candidates or []) if scope.in_scope(u)}

        passive_pages: "set[str]" = set()
        if not local and not cfg.skip_archives:
            provs = [("wayback", source_wayback), ("otx", source_otx),
                     ("urlscan", source_urlscan), ("commoncrawl", source_commoncrawl),
                     ("crtsh", source_crtsh)]
            _vlog(cfg, f"passive: querying {len(provs)} sources (budget {cfg.passive_budget}s)...")
            task_name = {asyncio.ensure_future(f(engine, cfg.domain)): name for name, f in provs}
            done, pending = await asyncio.wait(
                list(task_name.keys()), timeout=cfg.passive_budget)
            for t in pending:
                t.cancel()
                coverage["providers"][task_name[t]] = "timeout"
                _vlog(cfg, f"passive {task_name[t]}: TIMEOUT (exceeded {cfg.passive_budget}s budget)")
            for t in done:
                name = task_name[t]
                try:
                    res = t.result()
                except Exception as e:
                    res = SourceResult(set(), f"error: {type(e).__name__}", "")
                if not isinstance(res, SourceResult):
                    res = SourceResult(res if isinstance(res, set) else set(), "ok", "")
                if name == "crtsh":
                    subs = {s for s in res.urls if scope.in_scope("https://" + s + "/")}
                    subdomains |= subs
                    coverage["providers"]["crtsh"] = f"{res.status} ({len(subs)} subs)"
                    _vlog(cfg, f"passive crtsh: {res.status} -> {len(subs)} in-scope subdomains")
                else:
                    in_scope = {u for u in res.urls if scope.in_scope(u)}
                    js = {u for u in in_scope if looks_like_js_url(u)}
                    pages = {u for u in in_scope if u not in js and _is_page(u)}
                    candidates |= js
                    passive_pages |= pages
                    coverage["providers"][name] = (
                        f"{res.status} ({len(res.urls)} urls, {len(js)} js, {len(pages)} pages)")
                    _vlog(cfg, f"passive {name}: {res.status} -> {len(res.urls)} urls "
                               f"({len(js)} js, {len(pages)} page-seeds)")

            # subfinder (if installed) widens subdomain discovery beyond crt.sh
            if tool_on_path("subfinder"):
                try:
                    sf = await bridge_subdomains(cfg.domain, scope)
                except Exception:
                    sf = set()
                new = sf - subdomains
                subdomains |= sf
                coverage["providers"]["subfinder"] = f"ok ({len(sf)} subs, {len(new)} new)"
                _vlog(cfg, f"bridge subfinder: {len(sf)} subdomains ({len(new)} new beyond crt.sh)")

        # --- 2. Seeds + active crawl ---
        # Seed the crawler with homepage + subdomain roots + passive page URLs
        # (OTX/urlscan/wayback pages are live pages that *contain* the JS bundles).
        seeds = list(cfg.seeds) if cfg.seeds else [
            f"https://{cfg.domain}/", f"http://{cfg.domain}/"]
        if cfg.allow_subs:
            seeds += ["https://" + s + "/" for s in list(subdomains)[:200]]
        seeds += list(passive_pages)[:300]
        if not cfg.passive:
            _vlog(cfg, f"crawl: {len(set(seeds))} seed URLs "
                       f"({len(passive_pages)} from passive), depth {cfg.depth}...")
            spider = Spider(engine, scope, cfg)
            js_from_crawl, html_records = await spider.crawl(seeds)
            candidates |= {u for u in js_from_crawl if scope.in_scope(u)}
            coverage["techniques"]["crawl_js"] = len(js_from_crawl)
            coverage["techniques"]["html_pages_crawled"] = len(html_records)
            # per-host breakdown: which subdomains served JS, which were blocked/dead
            host_report = {h: _host_summary(hs) for h, hs in spider.host_stats.items()}
            coverage["crawl_hosts"] = dict(sorted(host_report.items()))
            js_hosts = sorted(((h, hs["js"]) for h, hs in spider.host_stats.items() if hs["js"]),
                              key=lambda x: -x[1])
            blocked = [h for h, s in host_report.items() if s in ("403", "401", "429")]
            coverage["techniques"]["hosts_crawled"] = len(host_report)
            coverage["techniques"]["hosts_with_js"] = len(js_hosts)
            coverage["techniques"]["hosts_blocked_4xx"] = len(blocked)
            _vlog(cfg, f"crawl: found {len(js_from_crawl)} JS from {len(html_records)} pages "
                       f"across {len(host_report)} hosts")
            _vlog(cfg, f"crawl: JS on {len(js_hosts)} hosts, {len(blocked)} blocked(4xx), "
                       f"{sum(1 for s in host_report.values() if s in ('timeout', 'error/unreachable'))} dead")
            for h, n in js_hosts[:25]:
                _vlog(cfg, f"    JS host: {h} -> {n}")
            if blocked:
                _vlog(cfg, f"    blocked (WAF/auth?): {', '.join(sorted(blocked)[:20])}")
        else:
            _vlog(cfg, f"passive mode: skipping crawl ({len(passive_pages)} page-seeds unused; "
                       f"run without --passive to crawl them for live JS)")

        # --- 2b. Headless render (opt-in): exact browser Network-tab parity ---
        if cfg.render:
            if not HAVE_PLAYWRIGHT:
                coverage["techniques"]["render"] = "playwright-missing"
                _vlog(cfg, "render: playwright not installed - skipping "
                           "(pip install playwright && playwright install chromium)")
            else:
                _vlog(cfg, f"render: launching headless Chromium on up to "
                           f"{cfg.render_pages} pages...")
                rjs, rstatus = await render_pages(cfg, scope, seeds)
                in_scope_rjs = {u for u in rjs if scope.in_scope(u)}
                candidates |= in_scope_rjs
                coverage["techniques"]["render_js"] = len(in_scope_rjs)
                coverage["techniques"]["render_status"] = rstatus
                _vlog(cfg, f"render: browser loaded {len(rjs)} JS "
                           f"({len(in_scope_rjs)} in-scope), status={rstatus}")

        # --- 3. Opportunistic Go-tool bridge ---
        try:
            bridged = set() if local else await bridge_augment(cfg.domain, scope)
        except Exception:
            bridged = set()
        candidates |= bridged
        coverage["techniques"]["bridge_js"] = len(bridged)

        # --- 4. Recursive probe + extract to a fixpoint ---
        records: "list[FileRecord]" = []
        probed: "set[str]" = set()
        queue = {u for u in candidates if scope.in_scope(u)}
        _vlog(cfg, f"discovery complete: {len(queue)} JS candidates to probe")
        iterations = 0
        while queue and len(probed) < cfg.max_urls and iterations < 6:
            iterations += 1
            batch = [u for u in queue if u not in probed][:cfg.max_urls - len(probed)]
            queue = set()
            _vlog(cfg, f"probe iteration {iterations}: {len(batch)} candidates "
                       f"({sum(1 for r in records if r.is_js)} JS found so far)")
            probe_results = await asyncio.gather(
                *[prober.probe(u, "discovery") for u in batch], return_exceptions=True)
            new_urls: "set[str]" = set()
            for u, rec in zip(batch, probe_results):
                probed.add(u)
                if isinstance(rec, Exception) or rec is None:
                    continue
                records.append(rec)
                if not rec.is_js:
                    continue
                text = rec.text or ""
                await self._extract_sourcemap(engine, rec)
                new_urls |= reconstruct_webpack_chunks(text, rec.url)
                new_urls |= {u2 for u2 in extract_js_links(text, rec.url) if looks_like_js_url(u2)}
                low = rec.url.lower()
                if low.endswith(("asset-manifest.json", "chunk-manifest.json")):
                    new_urls |= parse_asset_manifest(text, rec.url)
                if low.endswith("manifest.json"):
                    new_urls |= parse_vite_manifest(text, rec.url)
                if "buildmanifest" in low:
                    new_urls |= parse_next_build_manifest(text, rec.url)
            for u in new_urls:
                if u not in probed and scope.in_scope(u):
                    queue.add(u)
        coverage["techniques"]["total_probed"] = len(probed)
        coverage["techniques"]["js_files"] = sum(1 for r in records if r.is_js)
        coverage["iterations"] = iterations

        # --- 5. Analyze ---
        if not cfg.no_analyze:
            for rec in records:
                if not rec.is_js:
                    continue
                rec.secrets = scan_secrets(rec.text or "")
                rec.endpoints = scan_endpoints(rec.text or "")
                rec.score = score_record(rec, rec.secrets, rec.endpoints)

        # --- 6. Validate (opt-in) ---
        if cfg.validate:
            pairs = [(rec, s) for rec in records for s in (rec.secrets or [])]
            vres = await asyncio.gather(
                *[validate_secret(engine, s) for _, s in pairs], return_exceptions=True)
            for (rec, _s), vr in zip(pairs, vres):
                if isinstance(vr, dict):
                    rec.validated.append(vr)

        await engine.close()

        sev_counts: dict = {}
        for rec in records:
            for s in (rec.secrets or []):
                sev_counts[s.severity] = sev_counts.get(s.severity, 0) + 1
        findings = {
            "secret_severity_counts": sev_counts,
            "files_with_secrets": sum(1 for r in records if r.secrets),
            "total_secrets": sum(len(r.secrets or []) for r in records),
            "total_endpoints": sum(len(r.endpoints or []) for r in records),
            "source_maps": sum(1 for r in records if r.sourcemap_url),
        }
        return RunState(cfg.domain, records, coverage, findings, json_only=cfg.json_only)

    async def _extract_sourcemap(self, engine: HttpEngine, rec: FileRecord) -> None:
        text = rec.text or ""
        sm_url = find_sourcemap_url(text, rec.url)
        smap = None
        if sm_url and sm_url.startswith("data:"):
            rec.sourcemap_url = "inline"
            smap = parse_sourcemap(sourcemap_from_datauri(sm_url))
        elif sm_url:
            rr = await engine.get(sm_url)
            if not rr.error and rr.status == 200 and (rr.text or "").lstrip().startswith("{"):
                rec.sourcemap_url = sm_url
                smap = parse_sourcemap(rr.text)
        else:
            rr = await engine.get(rec.url + ".map")
            if not rr.error and rr.status == 200 and (rr.text or "").lstrip().startswith("{"):
                rec.sourcemap_url = rec.url + ".map"
                smap = parse_sourcemap(rr.text)
        if smap:
            rec.revealed_sources = revealed_source_paths(smap, rec.sourcemap_url or rec.url)
            if self.cfg.rebuild_src and self.cfg.outdir and smap.get("sourcesContent"):
                root = Path(self.cfg.outdir) / "original_src"
                for src, content in zip(smap.get("sources") or [], smap.get("sourcesContent") or []):
                    if not content:
                        continue
                    try:
                        p = _safe_child_path(root, src)
                        p.parent.mkdir(parents=True, exist_ok=True)
                        p.write_text(content, encoding="utf-8", errors="replace")
                    except Exception:
                        pass


@selftest("orchestrator.finds_hidden_chunk")
def _t_orch():
    base, stop = _serve({
        "/": ("text/html", b'<script src="/static/js/main.js"></script>'),
        "/static/js/main.js": ("application/javascript",
            b'a.p="/static/js/";t.u=function(e){return e+"."+{9:"beef"}[e]+".chunk.js"};'
            b'//# sourceMappingURL=main.js.map'),
        "/static/js/main.js.map": ("application/json",
            b'{"version":3,"sources":["../src/hidden.ts"]}'),
        "/static/js/9.beef.chunk.js": ("application/javascript",
            b'const k="AKIAIOSFODNN7EXAMPLE"'),
    })
    try:
        cfg = Config.defaults()
        cfg.domain = _host(base)
        cfg.seeds = [base + "/"]
        cfg.allow_subs = True   # local guard skips archives; crawl drives discovery
        st = _run(Orchestrator(cfg).run())
        urls = {r.url for r in st.records}
        assert any(u.endswith("/9.beef.chunk.js") for u in urls), urls  # hidden chunk
        assert any("hidden.ts" in p for r in st.records for p in r.revealed_sources), \
            [r.revealed_sources for r in st.records]
        # the hidden chunk's AWS key was analyzed
        assert st.findings["total_secrets"] >= 1, st.findings
    finally:
        stop()


# ----------------------------------------------------------------------------
# SECTION: CLI selftest
# ----------------------------------------------------------------------------
@selftest("cli.parse_all_flags")
def _t_cli():
    ns = build_argparser().parse_args(
        ["example.com", "--no-subs", "--passive", "--depth", "3", "--validate",
         "--concurrency", "5", "--proxy", "http://127.0.0.1:8080", "--header", "A: B",
         "--rebuild-src", "--no-analyze", "--rate", "3", "-o", "out"])
    cfg = Config.from_args(ns)
    assert cfg.domain == "example.com"
    assert cfg.allow_subs is False and cfg.passive and cfg.depth == 3
    assert cfg.validate and cfg.rebuild_src and cfg.no_analyze
    assert cfg.concurrency == 5 and cfg.rate == 3.0
    assert cfg.proxy.endswith("8080") and cfg.headers.get("A") == "B"
    assert cfg.outdir == "out"
    assert build_argparser().parse_args(["--check-deps"]).check_deps is True
    assert _normalize_domain("https://sub.EXAMPLE.com/path?x=1") == "sub.example.com"


@selftest("render.flags_and_graceful_absence")
def _t_render():
    ns = build_argparser().parse_args(["x.com", "--render", "--render-pages", "10"])
    cfg = Config.from_args(ns)
    assert cfg.render is True and cfg.render_pages == 10
    # when playwright is absent, render_pages degrades cleanly (never raises)
    if not HAVE_PLAYWRIGHT:
        js, status = _run(render_pages(cfg, Scope("x.com"), ["https://x.com/"]))
        assert js == set() and "not installed" in status


# ----------------------------------------------------------------------------
# SECTION: Per-host mode - dedicated hunt + report for EVERY subdomain,
#          plus one combined report + an index. (--per-host)
# ----------------------------------------------------------------------------
def bucket_urls_by_host(urls) -> dict:
    """Group a set of URLs by their hostname."""
    out: dict = {}
    for u in urls:
        h = _host(u)
        if h:
            out.setdefault(h, set()).add(u)
    return out


def combine_states(apex: str, states: "list[RunState]", json_only: bool = False) -> RunState:
    """Merge per-host RunStates into one combined RunState (dedup by URL)."""
    records: "list[FileRecord]" = []
    seen: set = set()
    for st in states:
        for r in st.records:
            if r.url in seen:
                continue
            seen.add(r.url)
            records.append(r)
    sev: dict = {}
    for r in records:
        for s in (r.secrets or []):
            sev[s.severity] = sev.get(s.severity, 0) + 1
    findings = {
        "secret_severity_counts": sev,
        "files_with_secrets": sum(1 for r in records if r.secrets),
        "total_secrets": sum(len(r.secrets or []) for r in records),
        "total_endpoints": sum(len(r.endpoints or []) for r in records),
        "source_maps": sum(1 for r in records if r.sourcemap_url),
        "hosts": len(states),
    }
    coverage = {
        "mode": "per-host",
        "hosts_scanned": len(states),
        "hosts_with_js": sum(1 for st in states if any(r.is_js for r in st.records)),
        "total_js_files": sum(1 for r in records if r.is_js),
    }
    return RunState(apex, records, coverage, findings, json_only=json_only)


def render_index_html(apex: str, summaries: "list[dict]") -> str:
    """Index page linking every per-host report, ranked by JS count."""
    rows = []
    for s in sorted(summaries, key=lambda x: (-x["js"], x["host"])):
        rows.append(
            f"<tr><td class='h'><a href='hosts/{_esc(s['host'])}/report.html'>{_esc(s['host'])}</a></td>"
            f"<td>{_esc(s['status'])}</td><td class='n'>{s['js']}</td>"
            f"<td class='n'>{s['secrets']}</td><td class='n'>{s['endpoints']}</td></tr>")
    tot_js = sum(s["js"] for s in summaries)
    tot_sec = sum(s["secrets"] for s in summaries)
    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>GodJsGlitch - {_esc(apex)} (per-host)</title>
<style>
:root{{color-scheme:light dark}}
body{{font-family:system-ui,Segoe UI,Roboto,sans-serif;margin:0;background:#0d0d10;color:#e8e8ea}}
header{{padding:20px 24px;background:#15151a;border-bottom:1px solid #2a2a33}}
h1{{margin:0;font-size:20px}} .sub{{color:#9a9aa5;font-size:13px;margin-top:4px}}
.wrap{{padding:20px 24px}}
table{{width:100%;border-collapse:collapse;font-size:13px}}
th,td{{text-align:left;padding:8px 10px;border-bottom:1px solid #23232b}}
th{{background:#15151a;color:#9a9aa5}} td.n{{text-align:right;font-variant-numeric:tabular-nums}}
td.h{{word-break:break-all}} a{{color:#7aa2ff;text-decoration:none}}
@media (prefers-color-scheme:light){{body{{background:#fff;color:#111}}header,th{{background:#f6f6f8}}}}
</style></head><body>
<header><h1>GodJsGlitch &mdash; {_esc(apex)}</h1>
<div class="sub">per-host scan &middot; {len(summaries)} subdomains &middot; {tot_js} JS files &middot; {tot_sec} secret candidates
&middot; combined report: <a href="report.html">report.html</a> &middot; all URLs: <a href="js_urls.txt">js_urls.txt</a></div></header>
<div class="wrap"><table>
<thead><tr><th>Subdomain</th><th>Status</th><th>JS files</th><th>Secrets</th><th>Endpoints</th></tr></thead>
<tbody>{''.join(rows)}</tbody></table></div></body></html>"""


async def _sweep_wayback(engine: HttpEngine, apex: str) -> "set[str]":
    url = (f"http://web.archive.org/cdx/search/cdx?url=*.{apex}/*"
           f"&output=text&fl=original&collapse=urlkey&limit=100000")
    r = await _get_resilient(engine, url)
    return parse_wayback_cdx(r.text) if (not r.error and r.text) else set()


async def _sweep_commoncrawl(engine: HttpEngine, apex: str) -> "set[str]":
    r = await _get_resilient(engine, "https://index.commoncrawl.org/collinfo.json")
    if r.error or r.status != 200 or not r.text:
        return set()
    try:
        idx = json.loads(r.text)
    except Exception:
        return set()
    if not idx or not isinstance(idx, list) or not idx[0].get("cdx-api"):
        return set()
    r2 = await _get_resilient(engine, f"{idx[0]['cdx-api']}?url=*.{apex}&output=json&fl=url&limit=100000")
    return parse_commoncrawl(r2.text) if (not r2.error and r2.text) else set()


async def apex_passive_sweep(engine: HttpEngine, apex: str, budget: float) -> "set[str]":
    """Query archives domain-wide (all subdomains) once, return every URL."""
    provs = {
        asyncio.ensure_future(_sweep_wayback(engine, apex)): "wayback",
        asyncio.ensure_future(source_otx(engine, apex)): "otx",
        asyncio.ensure_future(source_urlscan(engine, apex)): "urlscan",
        asyncio.ensure_future(_sweep_commoncrawl(engine, apex)): "commoncrawl",
    }
    done, pending = await asyncio.wait(list(provs.keys()), timeout=budget)
    for t in pending:
        t.cancel()
    out: "set[str]" = set()
    for t in done:
        try:
            res = t.result()
        except Exception:
            res = set()
        out |= res.urls if isinstance(res, SourceResult) else (res if isinstance(res, set) else set())
    return out


async def enumerate_subdomains(engine: HttpEngine, apex: str, scope: Scope) -> "set[str]":
    """crt.sh + subfinder + apex + www -> in-scope hostnames."""
    hosts: "set[str]" = {apex, "www." + apex}
    try:
        cr = await source_crtsh(engine, apex)
        hosts |= cr.urls
    except Exception:
        pass
    try:
        hosts |= await bridge_subdomains(apex, scope)
    except Exception:
        pass
    return {h for h in hosts if scope.in_scope("https://" + h + "/")}


async def live_hosts(engine: HttpEngine, hosts: "set[str]") -> dict:
    """Probe each host root; return {host: (status, scheme)} for reachable ones."""
    async def probe(h):
        for scheme in ("https", "http"):
            r = await engine.get(f"{scheme}://{h}/")
            if not r.error and r.status:
                return h, r.status, scheme
        return h, None, None
    results = await asyncio.gather(*[probe(h) for h in hosts], return_exceptions=True)
    alive: dict = {}
    for res in results:
        if isinstance(res, Exception):
            continue
        h, status, scheme = res
        if status:
            alive[h] = (status, scheme)
    return alive


async def run_per_host(cfg: Config) -> RunState:
    """Enumerate subdomains, hunt each one independently, write per-host + combined reports."""
    apex = apex_of(cfg.domain)
    scope = Scope(apex, allow_subs=True)
    apex_out = Path(cfg.outdir)
    engine = HttpEngine(cfg)

    hosts = await enumerate_subdomains(engine, apex, scope)
    _vlog(cfg, f"per-host: {len(hosts)} subdomains from crt.sh/subfinder")

    sweep = set()
    if not cfg.skip_archives:
        _vlog(cfg, "per-host: apex-wide archive sweep (Wayback/OTX/URLScan/CommonCrawl)...")
        sweep = await apex_passive_sweep(engine, apex, cfg.passive_budget)
    buckets = bucket_urls_by_host(sweep)

    candidate_hosts = hosts | {h for h in buckets if scope.in_scope("https://" + h + "/")}
    _vlog(cfg, f"per-host: {len(candidate_hosts)} candidate hosts "
               f"({len(hosts)} enumerated + {len(buckets)} seen in archives); probing liveness...")
    alive = await live_hosts(engine, candidate_hosts)
    # dead hosts that had archived JS: keep those URLs for the combined list (unreachable-but-known)
    dead_archive_js = sorted({
        u for h, b in buckets.items() if h not in alive
        for u in b if looks_like_js_url(u) and scope.in_scope(u)})
    await engine.close()
    targets = set(alive) or {apex}
    # Scale connections-per-host so total (~host_concurrency * per_host) stays reasonable.
    per_host_conc = max(3, cfg.concurrency // max(1, cfg.host_concurrency))
    _vlog(cfg, f"per-host: {len(targets)} reachable; hunting with {cfg.host_concurrency} hosts "
               f"in parallel, {per_host_conc} connections each "
               f"({len(dead_archive_js)} archived JS on unreachable hosts kept)")

    sem = asyncio.Semaphore(max(1, cfg.host_concurrency))
    summaries: "list[dict]" = []
    states: "list[RunState]" = []

    async def hunt(h: str):
        async with sem:
            bucket = buckets.get(h, set())
            bjs = [u for u in bucket if looks_like_js_url(u)]
            bpages = [u for u in bucket if not looks_like_js_url(u) and _is_page(u)]
            hcfg = replace(
                cfg, domain=h, allow_subs=False, per_host=False, skip_archives=True,
                passive=False, extra_candidates=list(bjs),
                seeds=[f"https://{h}/", f"http://{h}/"] + bpages[:200],
                outdir=str(apex_out / "hosts" / h),
                concurrency=per_host_conc,
                max_pages=min(cfg.max_pages, 150), verbose=0)
            try:
                st = await Orchestrator(hcfg).run()
            except Exception:
                return None
            write_all(st, hcfg.outdir)
            njs = sum(1 for r in st.records if r.is_js)
            status = f"{alive.get(h, ('?',))[0]}" if h in alive else "archive-only"
            _vlog(cfg, f"per-host {h}: {njs} JS, {st.findings['total_secrets']} secrets")
            return st, {
                "host": h, "status": status, "js": njs,
                "secrets": st.findings["total_secrets"],
                "endpoints": st.findings["total_endpoints"],
            }

    results = await asyncio.gather(*[hunt(h) for h in sorted(targets)], return_exceptions=True)
    for res in results:
        if isinstance(res, Exception) or res is None:
            continue
        st, summary = res
        states.append(st)
        summaries.append(summary)

    combined = combine_states(apex, states, json_only=cfg.json_only)
    write_all(combined, apex_out)
    try:
        (apex_out / "index.html").write_text(render_index_html(apex, summaries), encoding="utf-8")
    except Exception:
        pass
    if dead_archive_js:
        try:
            (apex_out / "unreachable_archived_js.txt").write_text(
                "\n".join(dead_archive_js) + "\n", encoding="utf-8")
        except Exception:
            pass
    return combined


@selftest("perhost.helpers")
def _t_perhost():
    b = bucket_urls_by_host({"https://a.x.com/1.js", "https://a.x.com/2.js", "https://b.x.com/3.js"})
    assert b["a.x.com"] == {"https://a.x.com/1.js", "https://a.x.com/2.js"}
    assert b["b.x.com"] == {"https://b.x.com/3.js"}
    s1 = RunState("a.x.com", [FileRecord("https://a.x.com/1.js", set(), 200, "application/javascript",
                  9, "h1", True, "", secrets=[Secret("t", "m", 4.0, "high")])], {}, {})
    s2 = RunState("b.x.com", [FileRecord("https://b.x.com/3.js", set(), 200, "application/javascript",
                  9, "h3", True, "")], {}, {})
    comb = combine_states("x.com", [s1, s2])
    assert len(comb.records) == 2 and comb.findings["total_secrets"] == 1
    assert comb.coverage["hosts_scanned"] == 2 and comb.coverage["total_js_files"] == 2
    html = render_index_html("x.com", [
        {"host": "a.x.com", "status": "200", "js": 2, "secrets": 1, "endpoints": 5},
        {"host": "b.x.com", "status": "200", "js": 1, "secrets": 0, "endpoints": 0}])
    assert "a.x.com/report.html" in html and "x.com" in html


# @@INSERT_SECTIONS_ABOVE@@


# ----------------------------------------------------------------------------
# CLI / entrypoint
# ----------------------------------------------------------------------------
def cmd_check_deps() -> int:
    print("GodJsGlitch dependency report")
    print("  python        :", sys.version.split()[0])
    print("  httpx         :", "yes" if HAVE_HTTPX else "no (fallback: requests/urllib)")
    print("  requests      :", "yes" if HAVE_REQUESTS else "no")
    print("  tldextract    :", "yes" if HAVE_TLDEXTRACT else "no (fallback: builtin TLD heuristic)")
    print("  beautifulsoup4:", "yes" if HAVE_BS4 else "no (fallback: regex HTML parsing)")
    print("  rich          :", "yes" if HAVE_RICH else "no (plain output)")
    print("  playwright    :", "yes (--render available)" if HAVE_PLAYWRIGHT
          else "no (--render needs: pip install playwright && playwright install chromium)")
    for tool in ("katana", "gau", "subfinder", "subjs", "waybackurls"):
        print(f"  {tool:<14}:", "on PATH" if shutil.which(tool) else "absent (native fallback)")
    return 0


def _normalize_domain(d: str) -> str:
    d = d.strip()
    if "://" in d:
        d = urllib.parse.urlsplit(d).netloc or d
    d = d.split("/")[0]
    return d.lower().strip().strip(".")


def build_argparser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="godjsglitch",
        description="GodJsGlitch - hunt every JavaScript file for a domain (live, historical, hidden).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="examples:\n"
               "  python godjs.py example.com\n"
               "  python godjs.py example.com --passive --validate\n"
               "  python godjs.py example.com --no-subs --proxy http://127.0.0.1:8080\n"
               "  python godjs.py --check-deps\n"
               "  python godjs.py --selftest",
    )
    p.add_argument("domain", nargs="?", help="target domain, e.g. example.com")
    # scope & discovery
    g1 = p.add_argument_group("scope & discovery")
    g1.add_argument("--no-subs", action="store_true",
                    help="exact host only (default: apex-scoped *.target.tld)")
    g1.add_argument("--scope", metavar="FILE", help="explicit in-scope host list (one per line)")
    g1.add_argument("--passive", action="store_true",
                    help="passive archive sources only, no active crawl")
    g1.add_argument("--depth", type=int, default=2, help="crawl depth (default 2)")
    g1.add_argument("--max-urls", dest="max_urls", type=int, default=5000,
                    help="hard cap on total candidates (default 5000)")
    g1.add_argument("--max-pages", dest="max_pages", type=int, default=300,
                    help="max HTML pages to crawl, e.g. subdomain homepages (default 300)")
    g1.add_argument("--per-host", dest="per_host", action="store_true",
                    help="run a dedicated hunt for EVERY subdomain and write a separate "
                         "report per subdomain PLUS a combined report + index.html")
    g1.add_argument("--host-concurrency", dest="host_concurrency", type=int, default=4,
                    help="how many subdomains to hunt in parallel in --per-host mode (default 4)")
    # analysis
    g2 = p.add_argument_group("analysis")
    g2.add_argument("--no-analyze", dest="no_analyze", action="store_true",
                    help="skip secret/endpoint scan (discovery only)")
    g2.add_argument("--validate", action="store_true",
                    help="actively validate discovered secrets (opt-in; hits 3rd parties)")
    g2.add_argument("--rebuild-src", dest="rebuild_src", action="store_true",
                    help="write source-map original sources to disk")
    g2.add_argument("--render", action="store_true",
                    help="headless-browser mode: load pages in Chromium and capture "
                         "runtime-loaded JS (exact Network-tab parity; needs playwright)")
    g2.add_argument("--render-pages", dest="render_pages", type=int, default=25,
                    help="max pages to open in the browser when --render (default 25)")
    # engine
    g3 = p.add_argument_group("engine")
    g3.add_argument("--concurrency", type=int, default=20, help="max in-flight requests (default 20)")
    g3.add_argument("--rate", type=float, default=10.0, help="max req/sec per host (default 10)")
    g3.add_argument("--timeout", type=float, default=15.0, help="per-request timeout s (default 15)")
    g3.add_argument("--passive-timeout", dest="passive_timeout", type=float, default=45.0,
                    help="overall wall-clock cap for passive providers (default 45)")
    g3.add_argument("--proxy", help="route through a proxy, e.g. http://127.0.0.1:8080")
    g3.add_argument("--header", action="append", metavar="'K: V'",
                    help="extra header (repeatable; e.g. auth cookies)")
    g3.add_argument("--ua", help="custom User-Agent")
    # output & meta
    g4 = p.add_argument_group("output & meta")
    g4.add_argument("-o", "--out", dest="outdir", metavar="DIR",
                    help="output dir (default ./godjs_out/DOMAIN)")
    g4.add_argument("--json-only", dest="json_only", action="store_true",
                    help="write only results.json")
    g4.add_argument("-v", "--verbose", action="count", default=0, help="verbosity (-v, -vv)")
    g4.add_argument("--check-deps", action="store_true",
                    help="report available optional libs/tools and exit")
    g4.add_argument("--selftest", nargs="?", const="", metavar="PATTERN",
                    help="run built-in offline tests (optional substring filter) and exit")
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

    cfg = Config.from_args(ns)
    cfg.domain = _normalize_domain(cfg.domain)
    if not cfg.domain:
        print("error: could not parse a domain from input", file=sys.stderr)
        return 2
    cfg.outdir = cfg.outdir or str(Path("godjs_out") / cfg.domain)

    mode = "per-host" if cfg.per_host else ("passive" if cfg.passive else "full")
    print(f"[godjsglitch] hunting JS for {cfg.domain}  "
          f"(mode={mode}, subs={'on' if cfg.allow_subs else 'off'}, "
          f"render={'yes' if cfg.render else 'no'}, "
          f"validate={'yes' if cfg.validate else 'no'}, backend={HttpEngine(cfg).backend})")
    t0 = time.time()
    try:
        if cfg.per_host:
            state = asyncio.run(run_per_host(cfg))
        else:
            state = asyncio.run(Orchestrator(cfg).run())
            write_all(state, cfg.outdir)
    except KeyboardInterrupt:
        print("\n[godjsglitch] interrupted", file=sys.stderr)
        return 130
    dt = time.time() - t0
    f = state.findings
    n = len([r for r in state.records if r.is_js])
    print(f"[godjsglitch] done in {dt:.1f}s: {n} JS files, "
          f"{f['files_with_secrets']} with secrets, {f['total_secrets']} secret candidates, "
          f"{f['source_maps']} source maps, {f['total_endpoints']} endpoints")
    print(f"[godjsglitch] output -> {cfg.outdir}{os.sep}  (js_urls.txt, results.json"
          f"{'' if cfg.json_only else ', report.html'})")
    if cfg.per_host:
        print(f"[godjsglitch] per-host: {state.coverage.get('hosts_scanned', 0)} subdomains scanned, "
              f"{state.coverage.get('hosts_with_js', 0)} served JS")
        print(f"[godjsglitch]   - per-subdomain reports: {cfg.outdir}{os.sep}hosts{os.sep}<host>{os.sep}")
        print(f"[godjsglitch]   - combined report + index: {cfg.outdir}{os.sep}index.html")
    top = sorted([r for r in state.records if r.is_js and r.score > 0],
                 key=lambda r: -r.score)[:10]
    if top:
        print("[godjsglitch] top-scored files:")
        for r in top:
            tags = ",".join(sorted({s.type for s in r.secrets})) if r.secrets else ""
            print(f"   {r.score:6.1f}  {r.url}  {tags}")

    tech = state.coverage.get("techniques", {})
    if tech.get("hosts_crawled"):
        print(f"[godjsglitch] crawl reach: {tech.get('hosts_with_js', 0)} hosts with JS, "
              f"{tech.get('hosts_blocked_4xx', 0)} blocked(4xx) of {tech['hosts_crawled']} crawled "
              f"(per-host breakdown in results.json -> coverage.crawl_hosts)")
    if tech.get("hosts_blocked_4xx"):
        print("[godjsglitch] note: some subdomains returned 4xx (WAF or auth-gated). To reach them, "
              "re-run with a real browser session: --header 'Cookie: <session>' [--proxy http://127.0.0.1:8080]")

    # When nothing turned up, explain WHY (provider status) and how to fix it.
    if n == 0:
        print("[godjsglitch] no JS files found. Provider status:")
        for name, stat in (state.coverage.get("providers") or {}).items():
            print(f"     {name:<12}: {stat}")
        hints = []
        if cfg.passive:
            hints.append("you ran --passive (archives only); re-run WITHOUT --passive "
                         "to crawl the live site and its pages for JS")
        else:
            hints.append("the site may block automated requests - try "
                         "--header 'Cookie: <session>' and/or --proxy, or raise --depth")
        hints.append("verify the domain resolves and is reachable from this host")
        hints.append("re-run with --verbose to see per-phase diagnostics")
        for h in hints:
            print(f"     hint: {h}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
