# Public HF Space runtime and source witness (Python)

This is a **bounded, read-only diagnostic** for the `SZLHOLDINGS` public Space inventory. The GitHub `szl-holdings` organization remains the source owner. It does not publish, build, merge, sign, restart, wake, train, or claim release admission.

Run from the repository root:

```bash
python tools/public_space_runtime_witness.py --output space-runtime-witness.json
python -m unittest discover -s tests -p test_public_space_runtime_witness.py
```

The script uses only the Python standard library at runtime and anonymous HTTP `GET` requests. It enumerates a bounded public Hub list and reads each Space's immutable repository revision, runtime stage and runtime-reported revision. It uses the SDK to select either `.hf.space` or `.static.hf.space`; this distinction prevents false HTTP 404 reports for static Spaces. Explicit Hub subdomains must be valid DNS host labels; an identifier with a dot/underscore and no trustworthy Hub subdomain is reported as unavailable rather than guessed. Root HTTP status is sampled for every discovered Space; `/readyz` is probed for a bounded set of product verticals as **HTTP status only** (404 can mean an unsupported route). No route is used to infer signing authority or production admission.

For A11oy only, the script independently queries the public GitHub `main` commit endpoint, the Space's `/api/a11oy/v1/honest` source declaration, and its telemetry-summary HTTP status. The GitHub SHA, HF repository SHA, HF runtime SHA, and served **self-declared** source SHA remain separate fields. A matched claim is labelled `DECLARED_MATCH_NOT_BYTE_ATTESTED` and never as deployed-byte parity. A mismatch is `DECLARED_MISMATCH`. Independent runtime verification and release authority are always `NOT_PROVEN`.

## Failure / completeness contract

- A non-200 Hub index, 429 rate limit, invalid JSON or a page containing 100 entries marks pagination incomplete. The Space count remains `null`, not `0`.
- Individual metadata, HTTP, timeout, invalid revision and runtime mismatches remain independent per-Space observations. Missing provider data cannot be interpreted as running, healthy, signed or deployed.
- GET response bodies are size-capped. The root request reads only 128 bytes; no uploaded source, model weight, secret, token, private dataset or user record is fetched.
- The CLI returns nonzero when the index is not complete. Failures cannot result in a green estate-wide certificate.
- State `RUNNING` and HTTP 200 prove neither a working endpoint contract nor model inference, tenancy, training, countersignatures, source parity, rollback or paid-provider authority.

### Initial observation, November 21, 2026

A separate anonymous public enumeration of 78 `SZLHOLDINGS` Spaces found **74 RUNNING with root HTTP 200**, **3 SLEEPING with root HTTP 503**, and **1 PAUSED with root HTTP 503**. Some critical verticals returned HTTP 503 or 404 for `/readyz` despite root HTTP 200; that is a route-specific observation, not an estate-wide conclusion. Repeating the census immediately afterward encountered HTTP 429, which is preserved as `index_error=HTTP_ERROR` and `pagination_complete=false` rather than claiming fresh completeness.

A11oy's public `/readyz` and telemetry-summary GETs returned HTTP 200, but its served `/api/a11oy/v1/honest` source declaration (`07d4012f8b3f9b4658a1a89c4a44e65a7a54424b`) differed from GitHub `main` (`aa85c9097f23e575b705e87a238f522752e252fb`). Its HF Space repository revision was `031cf0240562a320bed007b9d5db8ccdeeb4062e`. Thus source/deployment admission remains **HOLD**, requiring a separately authorized exact-source publication and independent served-image verification.

All observations are time-scoped and may change without this source file changing. The program does not mutate any provider or update GitHub state itself.
