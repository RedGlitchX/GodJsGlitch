# GodJS — Design Spec

**Date:** 2026-07-11
**Status:** Approved-for-planning
**Deliverable:** A single, portable, self-contained Python file `godjs.py`
**One-liner:** Give it a domain; it hunts every JavaScript file that exists — live, historical, lazy-loaded, and hidden — then analyzes and (optionally) proves impact.

---

## 1. Purpose & success criteria

Take a single domain and discover **all** JavaScript files associated with it, with an emphasis on the ones normal tooling misses: deleted/historical bundles, lazy-loaded webpack/Vite chunks that are never linked from any visible page, and original source revealed by source maps. Then analyze each file for secrets and endpoints, rank them, and optionally validate secrets against live services.

**Success = ** on a real target, GodJS finds strictly more JS than `katana -jc` alone, runs to completion on a machine with **no Go tooling installed**, and produces a ranked, deduped, evidence-backed report.

Concretely, a run is successful when:
- It completes on Python 3.9+ with only `httpx` (falls back to `requests`/stdlib if absent).
- It emits `js_urls.txt`, `results.json`, and a self-contained `report.html`.
- Every technique in §4 ran (or was explicitly skipped by a flag) and is accounted for in a coverage summary.
- Zero crashes on network errors; failed fetches are recorded, never fatal.

---

## 2. Constraints

- **Single file.** `godjs.py` is the whole tool. Supporting `README.md`, `requirements.txt`, and this spec live alongside it but the tool is one script you can `scp` anywhere.
- **No hard external dependencies.** Must run with the Python stdlib. `httpx` is used if importable (preferred, async); otherwise a `requests` thread-pool backend; otherwise stdlib `urllib`. Optional niceties (`rich`, `tldextract`, `bs4`) are used only if present.
- **No Go tools required.** `katana`, `gau`, `subfinder`, `subjs`, `waybackurls` are used *only if found on PATH* to augment results (the "bridge"). Their absence changes nothing about correctness.
- **Authorized-testing hygiene.** Configurable concurrency + per-host rate limiting; custom User-Agent/headers; scope guardrails; a passive-only mode; opt-in active validation. Any provider that ever needs an email uses `support@p-technocyber.com` (per workspace policy) — never a personal address.
- **Windows-first, cross-platform.** Paths via `pathlib`; no shell-isms; works under PowerShell and bash.

---

## 3. Architecture (single file, sectioned internally)

`godjs.py` is organized top-to-bottom into clearly delimited sections, each a small set of classes/functions with one job. Internal boundaries are enforced by section, not by module import, but each is independently unit-testable via `--selftest`.

| Section | Responsibility | Key surface |
|---|---|---|
| `Config` | Parsed CLI args + runtime settings | `Config.from_args()` |
| `HttpEngine` | Async fetch, rate-limit, retries, proxy, headers, backend selection | `await get(url)`, `await head(url)` |
| `Scope` | apex extraction, `*.target.tld` matching, OOS filtering | `Scope.in_scope(url)` |
| `sources.*` | Passive providers (each pure `async fetch()->set[url]`) | `wayback`, `commoncrawl`, `otx`, `urlscan`, `crtsh` |
| `Spider` | Active depth-N HTML crawler → script refs | `await crawl(seeds)` |
| `extract.sourcemap` | find + parse `.map`, emit `sources[]`, optional rebuild | `parse_sourcemap(text)` |
| `extract.webpack` | chunk-map + manifest parsing → reconstruct chunk URLs | `reconstruct_chunks(js, base)` |
| `extract.jsinjs` | `.js` refs + `import()` targets inside JS | `extract_js_links(js, base)` |
| `Fingerprint` | framework detect → targeted manifest paths | `detect(html, headers)` |
| `Prober` | liveness/metadata, URL + content-hash dedup, is-real-JS | `await probe(url)` |
| `analyze.secrets` | secret regexes + Shannon entropy + JWT decode | `scan_secrets(text)` |
| `analyze.endpoints` | LinkFinder-style path/endpoint extraction | `scan_endpoints(text)` |
| `analyze.score` | juice score → ranking | `score(filerec)` |
| `validate.live` | active secret validation (opt-in) | `await validate(secret)` |
| `Bridge` | opportunistic katana/gau/subfinder/subjs | `augment(domain)` |
| `report.*` | writers: txt, json, html | `write_all(state, outdir)` |
| `Orchestrator` | the recursive pipeline & fixpoint loop | `await run()` |
| `SelfTest` | inline unit tests over pure functions | `--selftest` |

---

## 4. Discovery techniques (all four, plus the recursive glue)

### 4.1 Passive archives (find historical / deleted JS)
Query, in parallel, and merge+dedupe `.js` URLs from:
- **Wayback CDX** — `http://web.archive.org/cdx/search/cdx?url=*.DOMAIN/*&output=json&collapse=urlkey&filter=original:.*\.js(\?.*)?$`
- **Common Crawl** — latest index via `https://index.commoncrawl.org/collinfo.json` then `?url=*.DOMAIN&output=json`, filter `.js`.
- **AlienVault OTX** — `https://otx.alienvault.com/api/v1/indicators/domain/DOMAIN/url_list?limit=500&page=N` (paginated).
- **URLScan.io** — `https://urlscan.io/api/v1/search/?q=domain:DOMAIN`; pull `page.url` + resource lists.
- **crt.sh** — `https://crt.sh/?q=%25.DOMAIN&output=json` → **subdomains** (feeds §4.5, not JS directly).

Each provider is isolated, times out independently, and a failure of one never aborts the others.

### 4.2 Active crawl (find live linked JS)
Async, depth-N (default 2), same-scope HTML crawler. From each fetched HTML page extract JS from: `<script src>`, `<link rel=preload|modulepreload as=script>`, `<script type=importmap>` entries, inline `import ... from '...'` module specifiers, and `data-src` script variants. New in-scope HTML pages are enqueued up to depth/pagecount caps. Inline scripts are captured and passed to the extractors too.

### 4.3 Source-map mining (reveal hidden original tree)
For every discovered JS file: read the trailing `//# sourceMappingURL=` comment and also try the `<url>.map` convention. Fetch the map, parse JSON, and emit each entry of `sources[]` as a revealed original path (hidden internal modules, component names, sometimes other bundles). With `--rebuild-src`, write `sourcesContent[]` to `original_src/` mirroring the tree.

### 4.4 Webpack / Vite / Next chunk enumeration (the killer)
Parse the runtime/main bundle for the chunk graph and reconstruct URLs for **every** lazy chunk — including admin/feature-flagged ones never referenced by any page:
- Webpack: locate `__webpack_require__.u`/`.p`, the chunk-id→hash map (`{123:"a1b2",...}`), and the filename template; reconstruct `PUBLICPATH + template(id,hash)`.
- CRA/asset manifests: `asset-manifest.json`, `chunk-manifest.json`.
- Next.js: `_next/static/.../_buildManifest.js`, `_ssgManifest.js`, `_app`/page chunks.
- Vite: `manifest.json` (`.vite/manifest.json`) → every `file`/`imports`.
All reconstructed URLs go through the Prober (§ dedup) — non-200s are dropped.

### 4.5 Recursive glue, subdomains, fixpoint
- **crt.sh + passive data** yield subdomains; each in-scope host is seeded into passive+active discovery (apex-scoped `*.target.tld`; `--no-subs` disables).
- **JS-in-JS** (§4.3 extractor `jsinjs`): `.js` string refs and dynamic `import('...')` targets inside fetched JS are re-queued.
- The orchestrator loops discovery→probe→extract until **no new in-scope URLs appear** (fixpoint), with a hard cap on iterations/total-URLs to guarantee termination.

---

## 5. Analysis & validation

- **`analyze.secrets`** (default on; `--no-analyze` to skip): a library of ~40 secret regexes (AWS `AKIA/ASIA`, GCP, Azure conn strings, Stripe `sk_live`, Slack/Discord webhooks, GitHub `ghp_`/`glpat-`, Firebase config, Google Maps, JWT, private keys, generic high-entropy `key=`/`token=`), plus Shannon-entropy gating to cut noise, plus JWT header/claim decode. Patterns mirror the workspace's `~/.claude/skills/jsmax/references/secret_patterns.md`.
- **`analyze.endpoints`**: LinkFinder-style regex to pull API paths, absolute/relative URLs, and interesting routes (`/api/`, `/admin`, `/internal`, `/graphql`).
- **`analyze.score`**: a juice score per file from size anomalies, config-shaped content, admin-ish path names, source-map availability, and secret-hint density → drives report ranking so the human reads the right 5 of 500 files first.
- **`validate.live`** (opt-in `--validate` only): AWS `sts:GetCallerIdentity` (SigV4, stdlib), Firebase config probe, Google Maps key check, Stripe key probe, Slack webhook ping (dry, no message), GitHub token `/user`. Each validator degrades to "unverified" on any error; **no destructive calls**.

---

## 6. CLI

```
python godjs.py DOMAIN [options]

Scope & discovery:
  --no-subs            exact host only (default: apex-scoped *.target.tld)
  --scope FILE         explicit in-scope host list (one per line)
  --passive            passive sources only, no active crawl
  --depth N            crawl depth (default 2)
  --max-urls N         hard cap on total candidates (default 5000)

Analysis:
  --no-analyze         skip secret/endpoint scan (discovery only)
  --validate           actively validate discovered secrets (opt-in)
  --rebuild-src        write source-map original sources to disk

Engine:
  --concurrency N      max in-flight requests (default 20)
  --rate N             max req/sec per host (default 10)
  --timeout S          per-request timeout (default 15)
  --proxy URL          route through a proxy (e.g. Burp 127.0.0.1:8080)
  --header 'K: V'      extra header (repeatable; auth cookies for authed crawl)
  --ua STRING          custom User-Agent

Output & meta:
  -o DIR               output dir (default ./godjs_out/DOMAIN)
  --json-only          write only results.json
  --check-deps         report which optional libs/tools are available
  --selftest           run inline unit tests (no network) and exit
  -v/-vv               verbosity
```

---

## 7. Output

`./godjs_out/<domain>/`
- `js_urls.txt` — clean, deduped, sorted final URL list (the "just give me the list" artifact).
- `results.json` — full per-file records: `{url, source[], http_status, content_type, bytes, sha256, is_js, sourcemap_url, revealed_sources[], secrets[], endpoints[], score, validated[]}` + a top-level `coverage` summary (per-technique counts, providers reached/failed, live vs historical).
- `report.html` — self-contained (inline CSS/JS), ranked table, per-file expandable evidence, coverage panel.
- `original_src/…` — only with `--rebuild-src`.

---

## 8. Error handling

- Every network op is wrapped; failures are recorded to the file record / coverage summary and never abort the run.
- Per-provider and per-host timeouts; global run has a soft wall-clock budget (`--timeout` is per-request; orchestrator has iteration/URL caps).
- Dedup by canonicalized URL first, then by `sha256` of body (collapses the same bundle served at many paths).
- Termination guaranteed by fixpoint + `--max-urls` + max-iteration caps.
- Malformed source maps / manifests are caught per-file; a parse failure logs and continues.

---

## 9. Testing

- **`--selftest`** runs inline unit tests (no network) over the pure functions, written test-first:
  - `parse_sourcemap` on a fixture map → correct `sources[]`.
  - `reconstruct_chunks` on a fixture webpack runtime → expected chunk URLs.
  - `extract_js_links` on fixture JS → correct `.js` + `import()` targets.
  - `scan_secrets` → hits the planted secrets, ignores planted decoys (entropy gate).
  - `scan_endpoints` → correct paths.
  - `Scope.in_scope` → apex logic, subdomain in/out, OOS filtering.
  - URL canonicalization/dedup.
- One **integration** check: spin a stdlib `http.server` over a fixture site (linked JS + a webpack manifest + a `.map`) in a thread and assert GodJS finds all planted files including the unlinked chunk. Live passive providers are never called in tests (mocked/skipped).
- CI-less: `python godjs.py --selftest` must exit 0.

---

## 10. Explicitly out of scope (YAGNI)

- Headless-browser JS rendering (no Playwright/node dependency) — the extractor+manifest approach recovers lazy chunks without a browser.
- DOM-XSS / postMessage / logic-bug hunting — that's the other skills' job; GodJS finds files + hardcoded leaks.
- Distributed/multi-machine scaling, DB persistence — a JSON checkpoint is enough for resumability.
