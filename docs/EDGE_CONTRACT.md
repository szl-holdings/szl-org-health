# Edge contract

The edge contract is a continuous check that the Cloudflare edge in front of
the estate does what the owner decided. For every host and path in
[`edge/contract.yaml`](../edge/contract.yaml), an **unpaid, unauthenticated**
client must receive the declared response. It closes THREAD_AUDIT gap C-33:
the coordinator's container cannot reach the zones, and the Cloudflare URL
Scanner only sends GET requests, so POST behaviour and the current state were
unverified.

`.github/workflows/edge-contract.yml` runs
[`edge/check_contract.py`](../edge/check_contract.py) from a GitHub-hosted
runner every six hours and on manual dispatch. It needs no credentials and no
secrets.

## What each class requires

| Class | An unpaid client must receive | Accepted outcomes |
|---|---|---|
| `free` | The surface, a redirect, or an origin authentication refusal. Never a 402. | `2xx`, `3xx`, `401/403-origin-auth` |
| `paid` | A 402 whose `PAYMENT-REQUIRED` header decodes (x402 v2) to the live rule: `amount` equal to the rule price in atomic units, plus `scheme`, `network`, `asset`, `payTo`, `x402Version` and `resource.url` equal to the probed URL. | `402-paywall` with matching terms only |
| `internal` | A 403 that is not a bot challenge. | `403-edge-block`, `403-access`, `403-origin-auth` |

A check may narrow its accepted outcomes with `accept:`. Naming an outcome
outside that class's default is a contract error, so a free or internal check
cannot accept a 402 (`paywall` or `payment-unparsed`) or a `challenge`. A paid
check always requires the exact terms and cannot set `accept`.

## Outcome labels

Every message starts with one of these labels, so a red run says why:

| Label | How it is recognised |
|---|---|
| `402-paywall` | HTTP 402 with exactly one `PAYMENT-REQUIRED` header that decodes to an x402 object with an `accepts` list. |
| `402-unparsed` | HTTP 402 without a decodable header. |
| `403-challenge` | `cf-mitigated: challenge`, or a Cloudflare challenge interstitial (`window._cf_chl_opt`, "Just a moment..."). The `/cdn-cgi/challenge-platform/` script reference also appears on WAF block pages since 2026-11-14 and is not a challenge marker. A challenge is bot protection, not the paywall, and never passes. |
| `403-edge-block` | A Cloudflare block page or plain-text block (`error code: 10xx`, "Sorry, you have been blocked"). |
| `403-access`, `302-access` | A Cloudflare Access refusal (`cf-access-aud` / `cf-access-domain` headers) or a redirect to a `*.cloudflareaccess.com` login. |
| `401-origin-auth`, `403-origin-auth` | Any other 401 or 403. |
| `5xx-origin` | Any 5xx. The message says whether the body is a Cloudflare error page, which means the edge could not get a valid response from the origin. |
| `2xx`, `3xx`, `404`, `4xx` | The status class. Redirects are recorded and never followed. |
| `transport-error` | No HTTP response: DNS, TCP connection, TLS handshake, request write, response headers or body transfer. All remain FAIL. |

For `transport-error`, the receipt now adds a bounded
`transport_failure` record with `attempted_phase`,
`exception_class`, `phase_completed: false` and
`provider_or_origin_attribution: NOT_ESTABLISHED`. The six attempted
phases are `DNS_LOOKUP` (socket address-resolution exception),
`TCP_CONNECT`, `TLS_HANDSHAKE`, `HTTP_REQUEST_WRITE`,
`HTTP_RESPONSE_HEADERS`, and `HTTP_RESPONSE_BODY`.
The original stdlib `HTTPSConnection` still performs default CA
validation and SNI; a small per-connection TCP hook marks the moment the
socket successfully connects before the TLS handshake. No extra HTTP
request, retry, redirect, account credential, custom certificate trust,
or new monitoring controller is introduced. DNS failure is distinguished
by `socket.gaierror` rather than assuming all connection timeouts are DNS.
For a timeout the phase names the **last attempted operation**; it is
not evidence that operation completed or which provider caused it.

A failure after a TLS handshake does not prove that Cloudflare Worker code,
an upstream ntfy provider, WAF, origin, or any other specific component
is responsible. A zero-byte response remains transport failure, not
HTTP 200/403/402, a qualified settlement or a healthy alert channel.
All classes retain their existing acceptance and fail-closed exit semantics.

The 403 split is a heuristic over response headers and the first 64 KiB of
the body. The receipt records the evidence each classification used
(`classification_evidence`), and an unrecognised 403 is reported as
`403-origin-auth`, not as a pass on its own: free and internal checks accept
it only because the contract says an origin refusal is acceptable there.

## Requests

- One request per declared method. GET everywhere; POST as well on the paid
  endpoints, because the products are POST and the Gateway charges GET by
  default (MONETIZATION_AUDIT G-09).
- POST sends the body `{}` with `Content-Type: application/json`. It fails the
  OpenAI-compatible request validators, so a POST that leaks past the paywall
  is rejected by the origin instead of starting a generation.
- User-Agent `szl-edge-contract/1 (+https://github.com/szl-holdings/szl-org-health)`.
  The live rules exempt User-Agents containing `szl-readiness`,
  `szl-mesh-orchestrator`, `szl-energy-operator`, `SZL-Estate-Release-Train`,
  `SZL-Vigil-Anatomy-Probe` or `Cloudflare-Healthchecks`. The loader refuses a
  contract whose probe User-Agent contains one of them.
- No cookies, no `Authorization`, no redirects followed, no retries, a
  15-second timeout per request, TLS certificate verification on.

## Outputs and exit codes

- `reports/edge-contract-receipt.json` (schema `szl.edge-contract-receipt/v1`)
  and `reports/edge-contract-receipt.json.sha256`. The receipt binds the
  contract bytes (`contract.sha256`), the GitHub run (`source`), the transport
  (`direct-https` live, `loopback-override` in tests) and one row per request:
  verdict, label, status, message, selected response headers, the Cloudflare
  origin timing when present, and the decoded x402 terms. Failed network
  probes additionally record the attempted transport phase and the stable
  exception class (not a statement of provider blame). It never stores
  response bodies.
- A Markdown table in the job summary, failures first.
- Exit `0` when every request passes, `1` when any fails, `2` when the
  contract or the command line is invalid (no receipt is written).

The workflow uploads the receipt even when the check fails; the failing check
step still fails the job.

## Running it

```bash
python -I -B edge/check_contract.py --validate-only     # parse and validate, no network
python -I -B edge/check_contract.py                     # live run; needs direct HTTPS to the zones
python -I -B edge/check_contract.py --only inference-completions
python -m unittest tests.test_edge_contract -v          # offline, local http.server stub
```

`--connect-to 127.0.0.1:PORT` exists only for the tests: it sends plain HTTP
to a loopback stub while keeping the contract Host header, accepts only
loopback addresses, and marks the receipt `loopback-override`.

## Contract format

`edge/contract.yaml` uses a strict YAML subset so the checker stays
standard-library only:

- block mappings with `snake_case` keys, block sequences (`- item`, indented
  under their key), and flow lists of scalars (`[GET, POST]`);
- scalars: double-quoted strings with JSON escapes, single-quoted strings,
  `true`, `false`, `null`, unsigned integers without leading zeros, and plain
  words made of letters, digits, `_`, `.`, `/` and `-` that start with a
  letter, `_` or `/`;
- `#` comments, LF line endings, spaces only.

Anything else is rejected with a line number: tabs, anchors, aliases, tags,
block scalars, flow mappings, multi-line plain scalars, duplicate keys and
plain values that YAML 1.1 readers resolve differently (`yes`, `on`, dates,
floats, hex). The schema is closed: unknown keys are errors.

The loader also checks the contract against itself. Every rule in
`rules_inventory` must be probed by a `paid` check or explained in
`unprobed_rules`; a paid check must name an inventory rule with audience
`everyone` and the same price; prices must lie within the Gateway's
1,000 to 100,000,000 atomic-unit range.

## How the contract was seeded (2026-11-06)

- **Rules.** The Monetization Gateway rules read at about 16:26Z, with the
  three rules the coordinator disabled at 16:27:21-25Z applied: the
  verified-bot $0.10 catch-all on a-11-oy.com and both a11oy.net rules. Four
  rules stay enabled: `/v1/completions` and `/v1/responses` on
  `inference.` (20000 atomic, everyone), `/v1/chat/` on every a-11-oy.com host
  (20000, everyone), and two verified-bot-only apex API rules (50000 and 25000).
- **Free surfaces.** The owner's decision ("charge API/MCP hosts only;
  websites, `/pricing`, the proof site, health and well-known stay free") and
  MONETIZATION_REPORT section 4.5.1, restricted to paths with evidence: a
  URL Scanner observation (`run3.log` before the change, `run4.log` after), a
  WAF or redirect rule, or the route in the serving repository. Entries
  without a live observation say "Not yet observed live" in `evidence`.
- **Paid terms.** The decoded header of scan `ab7465a9` (run4,
  `GET /v1/completions`, 16:34Z): `x402Version` 2, `exact`, `eip155:8453`,
  USDC `0x8335…2913`, payTo `0x50E9…D460`, amount 20000.
- **Internal paths.** The WAF custom rule "Block vLLM internals on inference
  host (/metrics /docs /openapi.json /redoc) except HQ Vigil", action `block`.

The seed is 29 checks and 32 requests: 22 free, 3 paid (GET and POST each),
4 internal. `not_covered` lists the hosts and paths deliberately left out and
why.

## What the first live runs can show

These are possibilities, not observations; this repository has no live run
yet.

- **POST on the paid endpoints may fail** with "POST reached the origin
  unpaid". The live rules carry no method list, and the Gateway charges GET by
  default. That is the unverified claim THREAD_AUDIT D-20 needs settled, and a
  failure is a Cloudflare rule change for the owner (add POST to the rule), not
  a contract change.
- **Surfaces without a bot-challenge skip may fail with `403-challenge`.**
  Both zones send a managed challenge to traffic Cloudflare scores as
  definitely automated (`sbfm_definitely_automated: managed_challenge`). On
  a-11-oy.com the WAF skips cover `/healthz`, `/api/a11oy/healthz`,
  `/api/a11oy/v1/honest`, `/robots.txt` and `/.well-known/*` on every host, the
  whole `inference.`, `mcp.` and `gpu2.` hosts, every host whose name contains
  `gpu`, and the apex `/api/a11oy/v1/` and `/v1/` paths. a11oy.net has no skip
  rule. If a GitHub-hosted runner is challenged, that is the estate-traffic
  owner action (THREAD_AUDIT C-25, MONETIZATION_AUDIT G-12), not a reason to
  weaken the contract.
- **A "Not yet observed live" path may fail with `404`.** Then the contract is
  wrong about that path; correct it in a reviewed change with the evidence,
  never by accepting 404 on a free surface.

## Recorded ntfy relay response-header timeout (November 18, 2026)

The public [scheduled Edge contract run](https://github.com/szl-holdings/szl-org-health/actions/runs/44211456274)
passed 30 of 31 requests; `ntfy.a11oy.net/` returned **no HTTP status**
and a read-timeout. In a separate bounded, no-credential, one-request
observation on November 18, 01:13:53–01:14:08 UTC, the
unchanged `ntfy-root` contract returned FAIL in 15,110 milliseconds.
The enhanced transport receipt classified it as
`attempted_phase=HTTP_RESPONSE_HEADERS`,
`exception_class=TimeoutError`, `phase_completed=false`,
`provider_or_origin_attribution=NOT_ESTABLISHED`. Its owner-local
private receipt SHA-256 is
`9a283397a5b97406cf8a22b7ce6bcdc791246b43f4b9b389d05d32e78bb6f036`.
A checksum binds bytes, not the account or provider identity.

The same request reached the HTTP response-wait phase after TCP and TLS
handshake; this rules out *that particular request's* initial DNS/TCP/TLS
failure but **does not identify** whether the Cloudflare Worker, custom
domain, WAF, upstream ntfy provider, or another component caused the
delay. It does not establish successful notification delivery.

**Owner acceptance required:** reconcile the declared free-root expectation
here with the source [alert-relay Worker runbook](https://github.com/szl-holdings/a11oy/tree/main/ops/alert-relay-worker),
which documents `GET /` as intentionally challenged. The canonical
Cloudflare owner must independently inspect the custom domain and deployed
Worker revision, permitted WAF rules, and upstream behavior, then run the
existing authenticated publisher's revision readback and permitted delivery
canary. **Do not** change `ntfy-root` to a passing class, silently remove it,
weaken Cloudflare access protection, or call a timed-out request healthy.
No security settings or production routing were changed by the diagnostic.

## Proof boundary

A passing run proves only that, at the recorded time, one unpaid request per
declared method from a GitHub-hosted runner received the declared class of
response, and for paid endpoints that the decoded payment terms equalled the
contract. It does **not** prove:

- what other clients receive: verified bots, browsers, other networks or
  countries, or clients that send an exempted User-Agent;
- that verified-bot-only rules are absent or correctly priced (an unverified
  runner is never charged by them), or that disabled rules stay disabled; the
  szl-estate-os Cloudflare drift check covers rule configuration;
- that a payment would settle, that any origin validates `PAYMENT-CONTEXT`,
  or that a paid request is served after payment (MONETIZATION_AUDIT G-03);
- availability, latency or any SLO: that is the autonomic SLO controller's job;
- that a 403 classification is exact; it is a recorded heuristic.

A failing run is a finding about the edge or the contract at that time. Fix
the edge, or change the contract in a reviewed PR when the owner's decision
changes. Do not relax an expectation to make a run green.

## Changing the contract

1. Record the owner decision or the rule change that motivates the edit.
2. Edit `edge/contract.yaml`: one entry per host and path, with `evidence`
   that names the source (a rule id, a scan, a route, a report section).
3. Run `python -I -B edge/check_contract.py --validate-only` and
   `python -m unittest tests.test_edge_contract -v`.
4. Open a PR. After merge, dispatch the workflow and read the receipt.
