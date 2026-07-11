# GodJsGlitch

A single-file, self-contained **JavaScript hunting engine** for authorized security testing.

Give it a domain and it finds **every** JavaScript file it can reach — live, historical,
lazy-loaded, and hidden — then analyzes each for secrets and endpoints, ranks them, and
(optionally) validates the secrets against live services.

Unlike the usual `katana | gau | httpx` bash pipelines, GodJS **needs none of those tools**.
It natively reimplements the whole methodology in pure Python and only *uses* the Go tools if
they happen to be on your PATH.

## Why it's different

- **5-source passive fan-out** — Wayback CDX, Common Crawl, AlienVault OTX, URLScan.io, crt.sh
  (finds deleted/historical JS the live site no longer links).
- **Source-map mining** — parses `//# sourceMappingURL` + `.map` `sources[]` to reveal the
  original module tree; `--rebuild-src` dumps the original source to disk.
- **Webpack / Vite / Next chunk reconstruction** — rebuilds URLs for lazy-loaded admin /
  feature-flagged chunks that are never linked from any page, then probes them.
- **Recursive JS-in-JS** discovery loop to a fixpoint.
- **Content-hash dedup**, **framework fingerprinting**, and a **juice score** so you read the
  right 5 of 500 files first.
- **Zero required dependencies**; opportunistic **Go-tool bridge**; proxy / auth-header support.

## Install

Nothing required. For best performance:

```bash
pip install -r requirements.txt   # all optional
```

## Usage

```bash
python godjs.py example.com                 # full hunt (discovery + analysis)
python godjs.py example.com --passive       # archives only, no active crawl
python godjs.py example.com --no-subs       # exact host only
python godjs.py example.com --scope scope.txt   # explicit in-scope host list
python godjs.py example.com --validate      # actively prove discovered secrets (opt-in)
python godjs.py example.com --rebuild-src   # write original source-map sources to disk
python godjs.py example.com --render        # headless browser: capture runtime-loaded JS (Network-tab parity)
python godjs.py example.com --proxy http://127.0.0.1:8080 --header 'Cookie: session=...'
python godjs.py --check-deps                # what's available on this machine
python godjs.py --selftest                  # run built-in offline tests (21 checks)
python godjs.py -h                          # all flags
```

Every network phase is time-bounded: `--timeout` caps each request, `--passive-timeout`
caps the whole passive-archive phase, and DNS-dead hosts are never retried — a slow or
unreachable source can never stall the run.

Output lands in `./godjs_out/<domain>/`:
- `js_urls.txt` — clean, deduped, sorted URL list
- `results.json` — full per-file metadata + coverage summary
- `report.html` — self-contained ranked report

## Exact browser (DevTools Network tab) parity: `--render`

By default GodJsGlitch does **static** discovery (fetch + parse + chunk reconstruction),
which finds all `<script src>` bundles plus hidden lazy chunks and historical JS. It does
**not** execute JavaScript, so purely runtime-injected scripts can be missed.

`--render` closes that gap: it drives **headless Chromium (Playwright)**, loads each page,
and captures every JS the browser actually loads — exactly like the DevTools Network tab —
then runs the normal secret/endpoint analysis on them.

```bash
pip install playwright && playwright install chromium   # one-time
python godjs.py example.com --render --render-pages 25
```

It's slower (a real browser per page), so it opens the top `--render-pages` seeds
(homepage + subdomain roots). Combine with `--proxy`/`--header` to render authenticated pages.

## Found 0 files?

The **active crawl is the primary JS finder** — it fetches the live site (and any
page URLs harvested from passive sources) and extracts every `<script src>`, chunk,
and source map. `--passive` **skips the crawl** and relies only on archives, which
are often incomplete or rate-limited, so a passive-only run can legitimately find
little. If you got nothing:

1. **Drop `--passive`** and run the default hunt: `python godjs.py example.com` — this crawls the live site.
2. Add **`--verbose`** to see per-provider status and per-phase diagnostics.
3. If the site blocks bots, pass a session: `--header 'Cookie: sessionid=...'` and/or `--proxy http://127.0.0.1:8080`.
4. Confirm the domain resolves and is reachable from your host.

When a run finds nothing, GodJsGlitch now prints each provider's status (e.g.
`wayback: timeout`, `otx: ok (2500 urls, 0 js, 1 pages)`) and concrete next steps.

## Safety

Authorized testing only. Configurable concurrency + per-host rate limiting, custom
User-Agent/headers, scope guardrails (`*.target.tld`, `--no-subs`, `--scope`), and
`--validate` is strictly opt-in (a default run makes no third-party validation calls).
