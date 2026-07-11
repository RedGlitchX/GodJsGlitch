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
import urllib.error
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
    max_pages: int = 100
    concurrency: int = 20
    rate: float = 10.0            # max requests/sec per host
    timeout: float = 15.0
    retries: int = 2
    proxy: "Optional[str]" = None
    headers: dict = field(default_factory=dict)
    ua: str = DEFAULT_UA
    validate: bool = False
    rebuild_src: bool = False
    no_analyze: bool = False
    outdir: "Optional[str]" = None
    scope_file: "Optional[str]" = None
    json_only: bool = False
    verbose: int = 0

    @classmethod
    def defaults(cls) -> "Config":
        return cls()


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
        h = {"User-Agent": self.cfg.ua, "Accept": "*/*"}
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

    async def _request(self, method: str, url: str) -> Response:
        host = _host(url)
        async with self._sem:
            await self._rate_wait(host)
            last_err = None
            for attempt in range(self.cfg.retries + 1):
                try:
                    return await self._dispatch(method, url)
                except Exception as e:  # noqa: BLE001 - network error -> retry then record
                    last_err = e
                    if attempt < self.cfg.retries:
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
