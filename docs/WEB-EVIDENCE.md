# Public web evidence lane

This repository now includes a small, dependency-light web evidence collector
at [`tools/web_evidence.py`](../tools/web_evidence.py). It is intended for
explicit, public URLs that SZL is allowed to read. It is not a search engine,
credential bypass, proxy rotator, or a production deployment by itself.

## Why this shape

The collector is an allowlisted control plane that can run without an API key:

- URLs are supplied explicitly or through a newline-delimited file.
- The host allowlist is required. HTTP and HTTPS are the only schemes.
- Userinfo, private-network targets, DNS failures, cross-host redirects, and
  oversized bodies fail closed. `allow_private_network` exists only for local
  fixture tests and must remain false in a deployment.
- `robots.txt` is fetched before the first page per host. A `Disallow` is
  `BLOCKED`; an unreachable server-side robots file is also `BLOCKED` under the
  RFC 9309 fail-closed rule. A 404/410 robots file is recorded as
  `ROBOTS_NOT_PUBLISHED` and still receives the explicit request delay.
- URL count, per-response bytes, total bytes, timeout, retry, and delay budgets
  are enforced for every run.
- Each URL produces one JSON-serializable receipt with status, content type,
  final URL, byte count, SHA-256 hashes, extractor name, robots decision, and
  evidence class. Text is omitted unless `--include-text` is passed.

These receipts are evidence about a fetch. They do not prove ownership,
authorization, publication, parity, runtime health, model quality, or legal
permission to reuse a page. Review the target's terms, access basis, and data
retention before enabling a scheduled job.

## Local no-key run

Use a small, reviewed URL list and an output directory owned by the job:

```powershell
$env:PYTHONDONTWRITEBYTECODE = "1"
$env:PYTHONPATH = "."
python -B -m tools.web_evidence `
  --url-file .\docs\reviewed-public-urls.txt `
  --allow-host github.com `
  --allow-host docs.python.org `
  --out .\run-evidence\web-receipts.jsonl
```

The command never needs a hosted scraper key. It uses Python's HTTP client and
`urllib.robotparser` for the policy gate. It does not launch a browser or
download model data.

## Open-source production adapters

For a larger scheduled crawl, keep this receipt contract and use an adapter:

1. **Scrapy (BSD-3-Clause)** for scheduling, sitemap/feed spiders, item
   pipelines, JSON Lines feeds, and resumable jobs. Set
   `ROBOTSTXT_OBEY = True`, enable AutoThrottle explicitly, cap per-domain
   concurrency, and use `FEED_MODE=create` or timestamped batches so a run
   cannot overwrite retained evidence.
2. **Trafilatura (Apache-2.0 from v1.8 onward)** for main-text and metadata
   extraction. Pin an exact version and retain its version in the receipt;
   versions before 1.8 use GPLv3+.
3. **scrapy-playwright (BSD-3-Clause) / Playwright Python (Apache-2.0)** only
   for allowlisted pages that require JavaScript. Browser binaries and their
   redistribution terms require a separate SBOM review. Use non-persistent
   browser contexts and hash the rendered HTML separately from the response.
4. **readability-lxml (Apache-2.0)** is an optional extraction fallback. Its
   cleaned output is not a sanitizer; render untrusted HTML only behind an
   explicit sanitizer and CSP.

The current module uses Trafilatura when it is already installed and falls
back to a standard-library HTML parser. Dependency installation, browser
binary availability, target-specific extraction quality, and any cloud or
provider deployment are **UNKNOWN** until a bounded run verifies them.

## Operational contract

Persist each run in a new directory named with a run ID. Store the JSONL
receipts, an environment/SBOM record, the exact URL input file, and a short
operator note. Keep raw response bytes only when the retention and license
basis are documented. A cache or SHA-256 is a replay aid and integrity
measurement; it is not an independent authorization or publication receipt.

The next safe integration step is a reviewed source list for the specific
public research targets, followed by a scheduled Scrapy job that emits this
receipt shape. No live scheduled job is enabled by this change.

## Primary references

- [Scrapy overview](https://docs.scrapy.org/en/latest/intro/overview.html) and
  [robots middleware](https://docs.scrapy.org/en/latest/topics/downloader-middleware.html#robotstxt)
- [Scrapy AutoThrottle](https://docs.scrapy.org/en/latest/topics/autothrottle.html)
  and [feed exports](https://docs.scrapy.org/en/latest/topics/feed-exports.html)
- [Trafilatura documentation](https://trafilatura.readthedocs.io/en/stable/)
- [Playwright Python library](https://playwright.dev/python/docs/library)
- [RFC 9309 — Robots Exclusion Protocol](https://www.rfc-editor.org/rfc/rfc9309.html)
- [Python `urllib.robotparser`](https://docs.python.org/3/library/urllib.robotparser.html)
