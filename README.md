# GodJS

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
python godjs.py example.com --validate      # actively prove discovered secrets (opt-in)
python godjs.py example.com --rebuild-src   # write original source-map sources to disk
python godjs.py --check-deps                # what's available on this machine
python godjs.py --selftest                  # run built-in offline tests
```

Output lands in `./godjs_out/<domain>/`:
- `js_urls.txt` — clean, deduped, sorted URL list
- `results.json` — full per-file metadata + coverage summary
- `report.html` — self-contained ranked report

## Safety

Authorized testing only. Configurable concurrency + per-host rate limiting, custom
User-Agent/headers, scope guardrails (`*.target.tld`, `--no-subs`, `--scope`), and
`--validate` is strictly opt-in (a default run makes no third-party validation calls).
