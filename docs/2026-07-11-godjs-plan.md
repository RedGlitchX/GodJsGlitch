# GodJS Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking. Tests run via `python godjs.py --selftest [substr]` — a built-in, dependency-free harness (no pytest).

**Goal:** Build `godjs.py`, a single portable tool that takes a domain and discovers every associated JavaScript file (live, historical, lazy-loaded, hidden), analyzes each for secrets/endpoints, ranks them, and optionally validates secrets.

**Architecture:** One self-contained Python file, sectioned internally (Config → HttpEngine → Scope → passive Sources → Spider → Extractors → Prober → Analyze → Validate → Bridge → Report → Orchestrator → SelfTest → CLI). Discovery is a recursive fixpoint loop. Network parts are thin async wrappers around pure, unit-tested parsers.

**Tech Stack:** Python 3.9+ stdlib. `httpx` used if importable (async), else `requests` thread-pool, else `urllib`. Optional `rich`/`tldextract`/`bs4` used only if present. No Go tools required.

## Global Constraints

- Single file `godjs.py`; supporting docs (`README.md`, `requirements.txt`, this plan/spec) sit alongside but the tool is one script.
- No hard third-party dependency. Every optional import is guarded; absence degrades gracefully, never crashes.
- No Go tool is ever required; katana/gau/subfinder/subjs are used only if on PATH.
- `--validate` is opt-in; a default run makes **no** third-party validation calls.
- Any email a provider ever needs = `support@p-technocyber.com`. Never a personal address.
- Windows-first: `pathlib` for paths, no shell-isms.
- Tests are pure/offline (local `http.server` fixtures only); no test ever calls a live passive provider.
- TDD throughout: failing selftest → minimal impl → green → commit.

---

### Task 0: Skeleton, git, selftest harness

**Files:**
- Create: `godjs/godjs.py`, `godjs/README.md`, `godjs/requirements.txt`, `godjs/.gitignore`

**Interfaces:**
- Produces: `@selftest(name)` decorator registering `() -> None` checks; `run_selftests(pattern: str|None) -> int` (returns failure count, prints results); `main(argv) -> int`; argparse supporting `--selftest [PATTERN]`.

- [ ] **Step 1: `git init` the project folder**

Run: `git init godjs` (in `C:\Users\Asus`). This folder is the repo; the user's home dir is NOT touched.

- [ ] **Step 2: Write skeleton with a self-registering test harness and one trivial passing test**

`godjs.py` top: shebang, docstring, `from __future__ import annotations`, stdlib imports. Add:
```python
_SELFTESTS: list[tuple[str, callable]] = []
def selftest(name):
    def deco(fn): _SELFTESTS.append((name, fn)); return fn
    return deco
def run_selftests(pattern=None):
    fails = 0
    for name, fn in _SELFTESTS:
        if pattern and pattern not in name: continue
        try: fn(); print(f"  PASS  {name}")
        except Exception as e: fails += 1; print(f"  FAIL  {name}: {type(e).__name__}: {e}")
    print(f"\n{len(_SELFTESTS)} tests, {fails} failed")
    return fails

@selftest("harness.sanity")
def _t_harness(): assert 1 + 1 == 2
```
`main()`: argparse with `--selftest` (nargs='?', const=''); if set, `sys.exit(1 if run_selftests(pattern or None) else 0)`.

- [ ] **Step 3: Run selftest, expect green**

Run: `python godjs.py --selftest`
Expected: `PASS harness.sanity` … `1 tests, 0 failed`, exit 0.

- [ ] **Step 4: Write README + requirements + .gitignore**

`requirements.txt` lists optional deps commented as optional (`httpx`, `rich`, `tldextract`, `beautifulsoup4`). `.gitignore`: `godjs_out/`, `__pycache__/`, `*.pyc`.

- [ ] **Step 5: Commit**

`git add -A && git commit -m "feat: godjs skeleton + selftest harness"`

---

### Task 1: URL canonicalization, JS detection, Scope

**Files:** Modify `godjs.py` (add `Scope` + URL utils section)

**Interfaces:**
- Produces: `canonicalize_url(u, base=None) -> str` (absolutize, drop fragment, normalize); `looks_like_js_url(u) -> bool`; `apex_of(host) -> str`; `class Scope(apex, allow_subs=True, oos=frozenset())` with `in_scope(url) -> bool` and `add_oos(host)`.

- [ ] **Step 1: Failing tests**
```python
@selftest("url.canonicalize")
def _t_canon():
    assert canonicalize_url("app.js", "https://x.com/a/b") == "https://x.com/a/app.js"
    assert canonicalize_url("https://X.com:443/p?q=1#f") == "https://x.com/p?q=1"
@selftest("url.looks_like_js")
def _t_js():
    assert looks_like_js_url("https://x.com/a.js?v=2")
    assert looks_like_js_url("https://x.com/a.chunk.mjs")
    assert not looks_like_js_url("https://x.com/a.css")
@selftest("scope.apex_and_membership")
def _t_scope():
    assert apex_of("a.b.example.co.uk") == "example.co.uk"
    s = Scope("example.com", allow_subs=True)
    assert s.in_scope("https://cdn.example.com/x.js")
    assert not s.in_scope("https://evil.com/x.js")
    s2 = Scope("example.com", allow_subs=False)
    assert not s2.in_scope("https://cdn.example.com/x.js")
    assert s2.in_scope("https://example.com/x.js")
```
- [ ] **Step 2: Run, expect FAIL** (`python godjs.py --selftest url.` and `scope.`) — NameError.
- [ ] **Step 3: Implement.** `apex_of` uses a small built-in multi-part-TLD set (`co.uk, com.br, com.au, co.in, co.jp, com.co, …`) falling back to last-2 labels; use `tldextract` if importable for accuracy. `canonicalize_url` via `urllib.parse.urljoin`+`urlsplit`, lowercasing host, stripping default ports and fragments. `looks_like_js_url` regex `\.(m?js)(\?|$)` and `.chunk.js`. `Scope.in_scope` parses host, checks apex suffix + subs flag + oos set.
- [ ] **Step 4: Run, expect PASS.**
- [ ] **Step 5: Commit** `feat: url canonicalization, js detection, scope guardrails`

---

### Task 2: HttpEngine (backend selection, async fetch, rate-limit, retries)

**Files:** Modify `godjs.py`

**Interfaces:**
- Produces: `@dataclass Response(url, status:int|None, headers:dict, text:str, content:bytes, error:str|None, final_url:str)`; `class HttpEngine(cfg)` with `async get(url) -> Response`, `async head(url) -> Response`, `async close()`. Honors concurrency semaphore, per-host rate (token bucket), timeout, retries, proxy, `headers`, `ua`. Backend auto-selected: httpx.AsyncClient → requests(ThreadPool via `asyncio.to_thread`) → urllib(to_thread).

- [ ] **Step 1: Failing test** (local fixture server helper `_serve(handler_map) -> (base_url, stop_fn)` using `http.server.ThreadingHTTPServer` on port 0):
```python
@selftest("http.get_ok_and_error")
def _t_http():
    base, stop = _serve({"/a.js": ("application/javascript", b"var a=1;")})
    try:
        eng = HttpEngine(Config.defaults())
        r = _run(eng.get(base + "/a.js"))
        assert r.status == 200 and "var a=1" in r.text
        r2 = _run(eng.get(base + "/missing"))
        assert r2.status == 404
        r3 = _run(eng.get("http://127.0.0.1:1/x"))  # closed port
        assert r3.error is not None and r3.status is None
    finally: stop()
```
(`_run(coro)` = `asyncio.new_event_loop().run_until_complete`; `_serve` returns after binding.)
- [ ] **Step 2: Run, expect FAIL.**
- [ ] **Step 3: Implement** backend selection with guarded imports; token-bucket rate limiter keyed by host; `asyncio.Semaphore(concurrency)`; retry loop (max 2) on transient errors; every exception captured into `Response.error`.
- [ ] **Step 4: Run, expect PASS.**
- [ ] **Step 5: Commit** `feat: async HttpEngine with backend fallback + rate limiting`

---

### Task 3: Prober, is-real-JS, content-hash dedup

**Files:** Modify `godjs.py`

**Interfaces:**
- Produces: `@dataclass FileRecord(url, sources:set, http_status, content_type, bytes, sha256, is_js, text)`; `class Prober(engine)` with `async probe(url, via:str) -> FileRecord|None` and `seen_hashes:set`; `is_real_js(content_type, body_head:str) -> bool`.

- [ ] **Step 1: Failing test**
```python
@selftest("prober.detect_and_dedup")
def _t_probe():
    base, stop = _serve({
      "/real.js": ("application/javascript", b"export const x=1"),
      "/dupe.js": ("application/javascript", b"export const x=1"),      # same body
      "/fake.js": ("text/html", b"<!doctype html><html></html>")})
    try:
        p = Prober(HttpEngine(Config.defaults()))
        r1 = _run(p.probe(base+"/real.js","test")); assert r1.is_js and r1.sha256
        r2 = _run(p.probe(base+"/dupe.js","test")); assert r2 is None  # dedup by hash
        r3 = _run(p.probe(base+"/fake.js","test")); assert r3 is not None and not r3.is_js
    finally: stop()
```
- [ ] **Step 2: Run, expect FAIL.**
- [ ] **Step 3: Implement.** `is_real_js`: true if content-type contains `javascript`/`ecmascript`, OR (path .js AND body doesn't start with `<!doctype`/`<html`). `probe` fetches, computes sha256, returns None if hash already in `seen_hashes` (else records it); keeps non-JS records flagged `is_js=False` (useful: some served as text/plain).
- [ ] **Step 4: Run, expect PASS.**
- [ ] **Step 5: Commit** `feat: prober with real-JS sniffing and content-hash dedup`

---

### Task 4: Source-map extractor

**Files:** Modify `godjs.py`

**Interfaces:**
- Produces: `find_sourcemap_url(js_text, base) -> str|None` (handles trailing `//# sourceMappingURL=`, data-URI, and `.map` convention); `parse_sourcemap(text) -> dict{sources:list, sourcesContent:list|None, sourceRoot:str}`; `revealed_source_paths(smap, base) -> list[str]`.

- [ ] **Step 1: Failing test**
```python
@selftest("sourcemap.find_and_parse")
def _t_smap():
    js = "var a=1;\n//# sourceMappingURL=app.js.map"
    assert find_sourcemap_url(js, "https://x.com/s/app.js") == "https://x.com/s/app.js.map"
    smap = parse_sourcemap('{"version":3,"sources":["../src/secret.ts","webpack://app/./util.js"],"sourceRoot":""}')
    paths = revealed_source_paths(smap, "https://x.com/s/app.js.map")
    assert any("secret.ts" in p for p in paths)
```
- [ ] **Step 2: Run, expect FAIL.**
- [ ] **Step 3: Implement.** Regex `//[#@]\s*sourceMappingURL=(\S+)`; if data-URI base64 → decode inline; else `canonicalize_url(m, base)`; also always offer `base + ".map"`. `parse_sourcemap` = `json.loads` guarded. `revealed_source_paths` joins `sourceRoot`+each source, keeps `webpack://` markers verbatim.
- [ ] **Step 4: Run, expect PASS.**
- [ ] **Step 5: Commit** `feat: source-map discovery + sources[] reconstruction`

---

### Task 5: Webpack / Vite / Next chunk reconstruction

**Files:** Modify `godjs.py`

**Interfaces:**
- Produces: `reconstruct_webpack_chunks(js_text, base) -> set[str]`; `parse_asset_manifest(json_text, base) -> set[str]`; `parse_vite_manifest(json_text, base) -> set[str]`; `parse_next_build_manifest(js_text, base) -> set[str]`.

- [ ] **Step 1: Failing test**
```python
@selftest("webpack.reconstruct")
def _t_wp():
    runtime = 'a.p="/static/";t.u=function(e){return"js/"+e+"."+{12:"deadbeef",7:"c0ffee"}[e]+".chunk.js"}'
    urls = reconstruct_webpack_chunks(runtime, "https://x.com/static/js/main.js")
    assert "https://x.com/static/js/12.deadbeef.chunk.js" in urls
    assert "https://x.com/static/js/7.c0ffee.chunk.js" in urls
@selftest("manifest.asset_vite_next")
def _t_mani():
    assert "https://x.com/static/js/2.abc.chunk.js" in parse_asset_manifest(
        '{"files":{"static/js/2.abc.chunk.js":"/static/js/2.abc.chunk.js"}}', "https://x.com/asset-manifest.json")
    assert any("index.9f.js" in u for u in parse_vite_manifest(
        '{"index.html":{"file":"assets/index.9f.js"}}', "https://x.com/.vite/manifest.json"))
    assert any(".js" in u for u in parse_next_build_manifest(
        'self.__BUILD_MANIFEST={"/":["static/chunks/pages/index-1.js"]}', "https://x.com/_next/static/x/_buildManifest.js"))
```
- [ ] **Step 2: Run, expect FAIL.**
- [ ] **Step 3: Implement.** For webpack: regex-extract the publicPath (`\.p\s*=\s*"([^"]*)"`), the id→hash map object literal (`{...}` following `\.u\s*=`), and the surrounding template string; do a literal template substitution per id. Manifests: `json.loads` + collect string values ending `.js`, absolutize via `canonicalize_url`. Next `_buildManifest`: regex all `"([^"]+\.js)"` string literals. All guarded; malformed → empty set.
- [ ] **Step 4: Run, expect PASS.**
- [ ] **Step 5: Commit** `feat: webpack/vite/next chunk-graph reconstruction (hidden chunks)`

---

### Task 6: HTML script extraction + JS-in-JS links

**Files:** Modify `godjs.py`

**Interfaces:**
- Produces: `extract_scripts_from_html(html, base) -> set[str]` (src, preload/modulepreload, importmap targets, `import ... from '...'`); `extract_html_links(html, base) -> set[str]` (crawl frontier `<a href>`); `extract_js_links(js_text, base) -> set[str]` (`.js` string refs + `import('...')`/`import("...")` dynamic targets).

- [ ] **Step 1: Failing test**
```python
@selftest("html.script_extraction")
def _t_html():
    html = '<script src="/a.js"></script><link rel="modulepreload" href="/b.js">' \
           '<script type="importmap">{"imports":{"x":"/c.js"}}</script><a href="/page2">'
    s = extract_scripts_from_html(html, "https://x.com/")
    assert {"https://x.com/a.js","https://x.com/b.js","https://x.com/c.js"} <= s
    assert "https://x.com/page2" in extract_html_links(html, "https://x.com/")
@selftest("jsinjs.links")
def _t_jsinjs():
    js = 'fetch("/api/x");var u="/static/lazy.js";import("/static/dyn.js")'
    s = extract_js_links(js, "https://x.com/app.js")
    assert "https://x.com/static/lazy.js" in s and "https://x.com/static/dyn.js" in s
```
- [ ] **Step 2: Run, expect FAIL.**
- [ ] **Step 3: Implement.** Prefer `bs4` if importable for HTML, else regex fallbacks (`<script[^>]+src=["']([^"']+)`, preload `rel=["'](?:module)?preload"[^>]+href`, importmap JSON parse, `import\s+.*?from\s+["']([^"']+)`). `extract_js_links`: regex `["']([^"']+\.m?js)["']` + `import\(\s*["']([^"']+)["']`. Absolutize + scope filter later.
- [ ] **Step 4: Run, expect PASS.**
- [ ] **Step 5: Commit** `feat: HTML script extraction + recursive JS-in-JS link discovery`

---

### Task 7: Passive source parsers

**Files:** Modify `godjs.py`

**Interfaces:**
- Produces pure parsers: `parse_wayback_cdx(text) -> set[str]`, `parse_otx(json_text) -> set[str]`, `parse_urlscan(json_text) -> set[str]`, `parse_commoncrawl(text) -> set[str]`, `parse_crtsh(json_text) -> set[str]` (returns hostnames). Plus async fetchers `async source_wayback(engine, domain) -> set`, … each wrapping engine+parser, each fully guarded.

- [ ] **Step 1: Failing test**
```python
@selftest("sources.parsers")
def _t_src():
    assert "https://x.com/a.js" in parse_wayback_cdx('[["original"],["https://x.com/a.js"],["https://x.com/b.css"]]')
    assert "https://x.com/o.js" in parse_otx('{"url_list":[{"url":"https://x.com/o.js"},{"url":"https://x.com/o.png"}]}')
    assert "https://x.com/u.js" in parse_urlscan('{"results":[{"page":{"url":"https://x.com/u.js"}}]}')
    assert "https://x.com/c.js" in parse_commoncrawl('{"url":"https://x.com/c.js"}\n{"url":"https://x.com/c.png"}')
    assert "cdn.x.com" in parse_crtsh('[{"name_value":"cdn.x.com\\nx.com"}]')
```
- [ ] **Step 2: Run, expect FAIL.**
- [ ] **Step 3: Implement.** Each parser tolerant of shape variance; filter JS parsers to `looks_like_js_url`. crt.sh splits `name_value` on newlines, strips `*.`. Async fetchers build the documented endpoint URLs (spec §4.1), call `engine.get`, pass body to parser, return set; any error → empty set + record provider failure.
- [ ] **Step 4: Run, expect PASS.**
- [ ] **Step 5: Commit** `feat: passive source parsers (wayback/otx/urlscan/commoncrawl/crtsh)`

---

### Task 8: Spider (active depth-N crawl)

**Files:** Modify `godjs.py`

**Interfaces:**
- Produces: `class Spider(engine, scope, cfg)` with `async crawl(seeds:list[str]) -> tuple[set[js_urls], list[FileRecord_html]]`. Respects `depth`, page cap, scope; collects scripts via Task 6 extractors and enqueues in-scope HTML links.

- [ ] **Step 1: Failing test** (local fixture site)
```python
@selftest("spider.depth_crawl")
def _t_spider():
    base, stop = _serve({
      "/": ("text/html", b'<script src="/app.js"></script><a href="/page2">'),
      "/page2": ("text/html", b'<script src="/admin.js"></script>'),
      "/app.js": ("application/javascript", b"1"),
      "/admin.js": ("application/javascript", b"2")})
    try:
        sc = Scope(_host(base), allow_subs=True)
        js,_ = _run(Spider(HttpEngine(Config.defaults()), sc, Config.defaults()).crawl([base+"/"]))
        assert any(u.endswith("/app.js") for u in js)
        assert any(u.endswith("/admin.js") for u in js)   # found only via depth-1 crawl
    finally: stop()
```
(`_host(base)` extracts `127.0.0.1`; treat as apex for the test via a scope that allows the literal host.)
- [ ] **Step 2: Run, expect FAIL.**
- [ ] **Step 3: Implement** BFS queue with visited set, depth tracking, page cap (`cfg.max_pages`, default 100), scope filtering on both JS and frontier links.
- [ ] **Step 4: Run, expect PASS.**
- [ ] **Step 5: Commit** `feat: async depth-N spider`

---

### Task 9: Analysis — secrets, endpoints, score

**Files:** Modify `godjs.py`

**Interfaces:**
- Produces: `@dataclass Secret(type, match, entropy, severity)`; `scan_secrets(text) -> list[Secret]`; `scan_endpoints(text) -> list[str]`; `shannon_entropy(s) -> float`; `decode_jwt(tok) -> dict|None`; `score_record(rec, secrets, endpoints) -> float`.

- [ ] **Step 1: Failing test**
```python
@selftest("analyze.secrets_endpoints_score")
def _t_an():
    txt = 'AKIAIOSFODNN7EXAMPLE k="sk_live_'+ "a"*24 +'" url="/api/v1/admin" x="lowentropydecoy"'
    types = {s.type for s in scan_secrets(txt)}
    assert "aws_access_key_id" in types and any("stripe" in t for t in types)
    assert "/api/v1/admin" in scan_endpoints(txt)
    assert shannon_entropy("aaaaaaaa") < shannon_entropy("aB3$xY9!zQ")
    hi = score_record(FileRecord("u",set(),200,"application/javascript",100,"h",True,txt),
                      scan_secrets(txt), scan_endpoints(txt))
    lo = score_record(FileRecord("u2",set(),200,"application/javascript",100,"h2",True,"benign"), [], [])
    assert hi > lo
```
- [ ] **Step 2: Run, expect FAIL.**
- [ ] **Step 3: Implement** ~40 named regexes (AWS AKIA/ASIA, Stripe `sk_live`/`pk_live`, Google API `AIza`, GCP, Slack `xox[baprs]`/webhook, Discord webhook, GitHub `ghp_`/`gho_`, GitLab `glpat-`, Firebase `AIza`+`firebaseio`, JWT `eyJ...`, `-----BEGIN * PRIVATE KEY-----`, generic `(?:api[_-]?key|secret|token|password)\s*[:=]\s*["']([^"']{12,})`). Generic matches gated by `shannon_entropy(val) >= 3.5`. `scan_endpoints`: LinkFinder-style regex for paths/URLs. `score_record`: weighted sum (secrets*10 + admin-path*5 + has-sourcemap + size-anomaly + endpoint-count*0.1). Port the pattern set from `~/.claude/skills/jsmax/references/secret_patterns.md`.
- [ ] **Step 4: Run, expect PASS.**
- [ ] **Step 5: Commit** `feat: secret + endpoint extraction with entropy gating and juice scoring`

---

### Task 10: validate.live (opt-in) — builders tested, calls guarded

**Files:** Modify `godjs.py`

**Interfaces:**
- Produces: `aws_sigv4(secret_key, date, region, service, string_to_sign) -> str`; `build_sts_request(akid, secret) -> (url, headers)`; `async validate_secret(engine, secret:Secret) -> dict{type,status,detail}` dispatch (aws/firebase/gmaps/stripe/slack/github); non-`--validate` runs never call it.

- [ ] **Step 1: Failing test** (AWS documented SigV4 signing-key vector — deterministic, offline):
```python
@selftest("validate.sigv4_vector")
def _t_sig():
    # AWS docs example: signing key for 20120215/us-east-1/iam, secret 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'
    import hmac, hashlib
    k = derive_signing_key("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY","20120215","us-east-1","iam")
    assert k.hex() == "f4780e2d9f65fa895f9c67b32ce1baf0b0d8a43505a000a1a9e090d414db404d"
```
- [ ] **Step 2: Run, expect FAIL.**
- [ ] **Step 3: Implement** `derive_signing_key` per AWS SigV4 (`HMAC("AWS4"+key, date) → region → service → "aws4_request"`); `build_sts_request` for `GetCallerIdentity`; other validators build minimal read-only probes; `validate_secret` wraps each in try/except → `unverified` on error. **No destructive calls anywhere.**
- [ ] **Step 4: Run, expect PASS.**
- [ ] **Step 5: Commit** `feat: opt-in secret validation (SigV4 + read-only probes)`

---

### Task 11: Reporters (txt / json / html)

**Files:** Modify `godjs.py`

**Interfaces:**
- Produces: `write_urls_txt(records, path)`; `write_results_json(state, path)`; `render_html(state) -> str`; `write_all(state, outdir)`. `state` = `@dataclass RunState(domain, records:list[FileRecord], coverage:dict, findings:dict)`.

- [ ] **Step 1: Failing test**
```python
@selftest("report.writers")
def _t_rep():
    recs = [FileRecord("https://x.com/b.js",{"crawl"},200,"application/javascript",10,"h1",True,""),
            FileRecord("https://x.com/a.js",{"wayback"},200,"application/javascript",10,"h2",True,"")]
    import tempfile, os, json
    d = tempfile.mkdtemp()
    st = RunState("x.com", recs, {"total":2}, {})
    write_all(st, d)
    lines = open(os.path.join(d,"js_urls.txt")).read().split()
    assert lines == sorted(lines)   # sorted+deduped
    j = json.load(open(os.path.join(d,"results.json"))); assert j["coverage"]["total"]==2
    assert "<html" in render_html(st).lower() and "x.com" in render_html(st)
```
- [ ] **Step 2: Run, expect FAIL.**
- [ ] **Step 3: Implement** txt = sorted unique URLs; json = `asdict` of records + coverage + findings; html = self-contained template (inline CSS/JS), ranked-by-score table with expandable evidence + coverage panel.
- [ ] **Step 4: Run, expect PASS.**
- [ ] **Step 5: Commit** `feat: txt/json/self-contained-html reporters`

---

### Task 12: Bridge (opportunistic Go tools)

**Files:** Modify `godjs.py`

**Interfaces:**
- Produces: `tool_on_path(name) -> bool`; `parse_tool_lines(text) -> set[str]`; `async bridge_augment(domain, scope) -> set[str]` (runs katana/gau/subfinder/subjs if present, else empty).

- [ ] **Step 1: Failing test**
```python
@selftest("bridge.parse_and_absent")
def _t_bridge():
    assert parse_tool_lines("https://x.com/a.js\n\nhttps://x.com/b.js\n") == {"https://x.com/a.js","https://x.com/b.js"}
    # env has no Go tools -> augment returns empty, never raises
    assert _run(bridge_augment("example.com", Scope("example.com"))) == set()
```
- [ ] **Step 2: Run, expect FAIL.**
- [ ] **Step 3: Implement** `shutil.which` guard; `asyncio.create_subprocess_exec` with timeout; parse stdout lines; scope-filter; absence/any-error → empty set.
- [ ] **Step 4: Run, expect PASS.**
- [ ] **Step 5: Commit** `feat: opportunistic katana/gau/subfinder/subjs bridge`

---

### Task 13: Orchestrator (recursive fixpoint) + headline integration test

**Files:** Modify `godjs.py`

**Interfaces:**
- Produces: `class Orchestrator(cfg)` with `async run() -> RunState`. Pipeline: gather seeds (passive ∥ crawl ∥ subdomains ∥ bridge) → probe → extract (sourcemap ∥ webpack ∥ jsinjs) → re-queue new in-scope URLs → loop to fixpoint (caps: `max_urls`, max 6 iterations) → analyze → optional validate → build coverage.

- [ ] **Step 1: Failing integration test** (the spec §9 headline: unlinked chunk reachable only via manifest + a `.map`):
```python
@selftest("orchestrator.finds_hidden_chunk")
def _t_orch():
    base, stop = _serve({
      "/": ("text/html", b'<script src="/static/js/main.js"></script>'),
      "/static/js/main.js": ("application/javascript",
          b'a.p="/static/js/";t.u=function(e){return e+"."+{9:"beef"}[e]+".chunk.js"};//# sourceMappingURL=main.js.map'),
      "/static/js/main.js.map": ("application/json", b'{"version":3,"sources":["../src/hidden.ts"]}'),
      "/static/js/9.beef.chunk.js": ("application/javascript", b'const k="AKIAIOSFODNN7EXAMPLE"')})
    try:
        cfg = Config.defaults(); cfg.domain=_host(base); cfg.seeds=[base+"/"]; cfg.allow_subs=True; cfg.passive=True
        st = _run(Orchestrator(cfg).run())
        urls = {r.url for r in st.records}
        assert any(u.endswith("/9.beef.chunk.js") for u in urls)      # hidden chunk found
        assert any("hidden.ts" in p for r in st.records for p in getattr(r,"revealed_sources",[]))
    finally: stop()
```
(`cfg.passive=True` skips live archive calls; seeds drive it. Passive providers must be skipped when `passive` seeds are supplied against localhost — guard providers to no-op on `127.0.0.1`.)
- [ ] **Step 2: Run, expect FAIL.**
- [ ] **Step 3: Implement** the loop; attach `revealed_sources` to FileRecord; enforce caps; assemble coverage dict (per-technique counts, providers reached/failed).
- [ ] **Step 4: Run, expect PASS** (and re-run full `--selftest` — all green).
- [ ] **Step 5: Commit** `feat: recursive fixpoint orchestrator (finds hidden chunks end-to-end)`

---

### Task 14: CLI, --check-deps, docs, end-to-end wiring

**Files:** Modify `godjs.py`, `README.md`

**Interfaces:**
- Produces: full argparse per spec §6; `Config.from_args(ns)`; `Config.defaults()`; `cmd_check_deps()`; `main()` dispatch (`--selftest` | `--check-deps` | run).

- [ ] **Step 1: Failing test**
```python
@selftest("cli.parse_all_flags")
def _t_cli():
    ns = build_argparser().parse_args(["example.com","--no-subs","--passive","--depth","3",
        "--validate","--concurrency","5","--proxy","http://127.0.0.1:8080","--header","A: B","-o","out"])
    cfg = Config.from_args(ns)
    assert cfg.domain=="example.com" and cfg.allow_subs is False and cfg.passive and cfg.depth==3
    assert cfg.validate and cfg.concurrency==5 and cfg.proxy.endswith("8080") and ("A","B") in cfg.headers.items() or cfg.headers.get("A")=="B"
```
- [ ] **Step 2: Run, expect FAIL.**
- [ ] **Step 3: Implement** the full argparser (every flag from §6), `Config` dataclass + `from_args`/`defaults`, `--check-deps` printing httpx/rich/tldextract/bs4 + katana/gau/subfinder/subjs availability, `main` dispatch that constructs `Orchestrator` and calls `write_all`. Write README usage + examples (`python godjs.py example.com`, `--passive`, `--validate`, `--rebuild-src`, `--check-deps`, `--selftest`).
- [ ] **Step 4: Run full `python godjs.py --selftest`, expect all PASS, exit 0.**
- [ ] **Step 5: Commit** `feat: full CLI, --check-deps, docs; godjs feature-complete`

---

## Self-Review (completed)

**Spec coverage:** §2 constraints → Task 0/2/14 (deps, single-file, no-Go). §4.1 passive → Task 7. §4.2 crawl → Task 8. §4.3 sourcemap → Task 4. §4.4 webpack/vite/next → Task 5. §4.5 recursion/subdomains/fixpoint → Task 6 (jsinjs) + Task 7 (crtsh) + Task 13. §5 analyze/validate → Task 9/10. §6 CLI → Task 14. §7 output → Task 11. §8 error handling → Tasks 2/3/7/13 (guarded). §9 testing → `--selftest` everywhere + Task 13 headline. §10 YAGNI honored (no headless browser).

**Placeholder scan:** none — every step has concrete code or an exact command.

**Type consistency:** `FileRecord` fields fixed in Task 3, reused verbatim in Tasks 9/11/13 (`revealed_sources` added as an attribute in Task 13, noted). `Config.defaults()`/`from_args` introduced Task 2/14 and used consistently. `RunState` introduced Task 11, produced by Task 13. `Response` (Task 2) consumed by 3/7/8/10/12.

**Note on git:** repo is `godjs/` (Task 0), not the home dir.
