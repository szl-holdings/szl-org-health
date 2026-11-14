# SPDX-License-Identifier: Apache-2.0
"""Offline contracts for the unpaid-client edge contract checker.

Every response comes from a local http.server stub on 127.0.0.1 that routes by
the Host header the checker sends; no test touches the network.
"""
from __future__ import annotations

import base64
import hashlib
import http.server
import io
import json
import os
import re
import socket
import tempfile
import threading
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

from edge.check_contract import (
    Check,
    ContractError,
    Observation,
    PaymentTerms,
    classify,
    decode_payment_required,
    evaluate,
    load_contract,
    main,
    parse_connect_to,
    parse_yaml_subset,
)
from tests.test_secret_workflow_boundary import _canonical_triggers, _uses_actions_secrets


ROOT = Path(__file__).resolve().parents[1]
CONTRACT = ROOT / "edge" / "contract.yaml"
WORKFLOW = ROOT / ".github" / "workflows" / "edge-contract.yml"
PAY_TO = "0x50E9B335ac233fcc5e87404367E7De253A63D460"
USDC_BASE = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913"


def payment_header(url: str, amount: int = 20000, **overrides) -> str:
    offer = {
        "scheme": "exact",
        "network": "eip155:8453",
        "amount": str(amount),
        "asset": USDC_BASE,
        "payTo": PAY_TO,
        "maxTimeoutSeconds": 3600,
        "extra": {"name": "USD Coin", "version": "2"},
    }
    offer.update(overrides.pop("offer", {}))
    document = {
        "x402Version": overrides.pop("version", 2),
        "error": "PAYMENT-SIGNATURE header is required",
        "resource": {"url": overrides.pop("resource_url", url)},
        "accepts": [offer],
    }
    return base64.b64encode(json.dumps(document).encode()).decode()


def paywall(url: str, **overrides) -> dict:
    return {
        "status": 402,
        "headers": [
            ("Content-Type", "text/html; charset=utf-8"),
            ("PAYMENT-REQUIRED", payment_header(url, **overrides)),
            ("Server-Timing", "cfEdge;dur=57,cfOrigin;dur=0,cfWorker;dur=2"),
        ],
        "body": b"<html><head><title>Payment required</title></head></html>",
    }


def ok(title: str = "page") -> dict:
    return {
        "status": 200,
        "headers": [("Content-Type", "text/html"), ("Server-Timing", "cfOrigin;dur=180")],
        "body": f"<html><title>{title}</title></html>".encode(),
    }


def redirect(location: str) -> dict:
    return {"status": 301, "headers": [("Location", location)], "body": b""}


def origin_json(status: int) -> dict:
    return {"status": status, "headers": [("Content-Type", "application/json")], "body": b'{"error":"auth"}'}


def edge_block() -> dict:
    return {"status": 403, "headers": [("Content-Type", "text/plain")], "body": b"error code: 1020"}


def challenge() -> dict:
    return {
        "status": 403,
        "headers": [("Content-Type", "text/html"), ("cf-mitigated", "challenge")],
        "body": b"<html><title>Just a moment...</title><script>window._cf_chl_opt={}</script></html>",
    }


def access_refusal() -> dict:
    return {
        "status": 403,
        "headers": [("Content-Type", "text/html"), ("Cf-Access-Aud", "redacted"), ("Cf-Access-Domain", "redacted")],
        "body": b"<html><title>Error \xe3\x83\xbb Cloudflare Access</title></html>",
    }


def cloudflare_502() -> dict:
    return {
        "status": 502,
        "headers": [("Content-Type", "text/html; charset=UTF-8")],
        "body": b"<html><title>a-11-oy.com | 502: Bad gateway</title></html>",
    }


def validation_error() -> dict:
    return {
        "status": 422,
        "headers": [("Content-Type", "application/json")],
        "body": b'{"detail":[{"loc":["body","prompt"],"msg":"Field required"}]}',
    }


class _StubHandler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *args) -> None:  # keep test output clean
        return None

    def _serve(self) -> None:
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length) if length else b""
        host = self.headers.get("Host", "")
        self.server.requests.append(
            {"method": self.command, "host": host, "path": self.path, "headers": dict(self.headers), "body": body}
        )
        spec = self.server.routes.get((host, self.command, self.path))
        if spec is None:
            spec = {"status": 404, "headers": [("Content-Type", "application/json")], "body": b'{"detail":"Not Found"}'}
        payload = spec.get("body", b"")
        self.send_response(spec["status"])
        for name, value in spec.get("headers", []):
            self.send_header(name, value)
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(payload)

    do_GET = _serve
    do_POST = _serve


class _Stub(http.server.ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, routes: dict) -> None:
        super().__init__(("127.0.0.1", 0), _StubHandler)
        self.routes = routes
        self.requests: list[dict] = []

    def __enter__(self) -> "_Stub":
        self._thread = threading.Thread(target=self.serve_forever, daemon=True)
        self._thread.start()
        return self

    def __exit__(self, *exc) -> None:
        self.shutdown()
        self.server_close()
        self._thread.join(timeout=5)

    @property
    def address(self) -> str:
        return f"127.0.0.1:{self.server_address[1]}"


def intended_edge(contract) -> dict:
    """Routes that answer every check the way the contract says the edge should."""
    special = {
        "www-redirect": redirect("https://a-11-oy.com/"),
        "proof-www-redirect": redirect("https://a11oy.net/"),
        "gdw-root": origin_json(401),
        "killinchu-root": origin_json(403),
    }
    routes = {}
    for check in contract.checks:
        for method in check.methods:
            if check.cls == "paid":
                spec = paywall(check.url)
            elif check.cls == "internal":
                spec = edge_block()
            else:
                spec = special.get(check.id, ok(check.id))
            routes[(check.host, method, check.path)] = spec
    return routes


class _ContractRun(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.receipt_path = Path(self.tmp.name) / "receipt.json"
        environment = unittest.mock.patch.dict(os.environ, {}, clear=False)
        environment.start()
        self.addCleanup(environment.stop)
        os.environ.pop("GITHUB_STEP_SUMMARY", None)
        self.contract = load_contract(CONTRACT)

    def run_checker(self, routes: dict, *extra: str) -> tuple[int, dict, _Stub, str]:
        with _Stub(routes) as stub:
            out, err = io.StringIO(), io.StringIO()
            with redirect_stdout(out), redirect_stderr(err):
                code = main(
                    [
                        "--contract",
                        str(CONTRACT),
                        "--receipt",
                        str(self.receipt_path),
                        "--connect-to",
                        stub.address,
                        *extra,
                    ]
                )
        receipt = json.loads(self.receipt_path.read_text(encoding="utf-8")) if self.receipt_path.exists() else {}
        return code, receipt, stub, out.getvalue() + err.getvalue()

    def rows(self, receipt: dict, check_id: str) -> dict[str, dict]:
        return {row["method"]: row for row in receipt["results"] if row["id"] == check_id}


class YamlSubsetTests(unittest.TestCase):
    def test_parses_mappings_sequences_scalars_and_comments(self) -> None:
        document = parse_yaml_subset(
            "---\n"
            "# heading\n"
            "name: plain-word  # trailing comment\n"
            "count: 20000\n"
            "zero: 0\n"
            "flag: true\n"
            "off_flag: false\n"
            "empty: null\n"
            "quoted: \"a # not a comment, \\u00e9\"\n"
            "single: 'it''s'\n"
            "path: /.well-known/mcp/server-card.json\n"
            "methods: [GET, \"POST\"]\n"
            "nothing: []\n"
            "nested:\n"
            "  inner: value\n"
            "  items:\n"
            "    - first\n"
            "    - key: one\n"
            "      other: two\n"
            "    -\n"
            "      deep: three\n"
        )
        self.assertEqual(
            document,
            {
                "name": "plain-word",
                "count": 20000,
                "zero": 0,
                "flag": True,
                "off_flag": False,
                "empty": None,
                "quoted": "a # not a comment, \u00e9",
                "single": "it's",
                "path": "/.well-known/mcp/server-card.json",
                "methods": ["GET", "POST"],
                "nothing": [],
                "nested": {
                    "inner": "value",
                    "items": ["first", {"key": "one", "other": "two"}, {"deep": "three"}],
                },
            },
        )

    def test_rejects_constructs_outside_the_subset(self) -> None:
        cases = {
            "tab": "key:\tvalue\n",
            "crlf": "key: value\r\n",
            "bom": "\ufeffkey: value\n",
            "duplicate key": "key: a\nkey: b\n",
            "yaml 1.1 boolean": "key: yes\n",
            "title-case boolean": "key: True\n",
            "date": "key: 2026-11-06\n",
            "float": "key: 1.5\n",
            "hex": "key: 0x1F\n",
            "leading zero": "key: 007\n",
            "space in plain": "key: two words\n",
            "colon in plain": "key: eip155:8453\n",
            "anchor": "key: &anchor value\n",
            "alias": "key: *anchor\n",
            "tag": "key: !tag value\n",
            "literal block": "key: |\n  text\n",
            "folded block": "key: >\n  text\n",
            "flow mapping": "key: {a: 1}\n",
            "nested flow": "key: [[a]]\n",
            "trailing comma": "key: [a, ]\n",
            "unterminated double": "key: \"open\n",
            "unterminated single": "key: 'open\n",
            "yaml-only escape": "key: \"\\x41\"\n",
            "text after quote": "key: \"a\" b\n",
            "missing value": "key:\nother: value\n",
            "indentless sequence": "key:\n- a\n",
            "multi-line plain": "key: a\n  b\n",
            "bad indentation": "key:\n    a: 1\n  b: 2\n",
            "second document": "a: 1\n---\nb: 2\n",
            "top-level sequence": "- a\n",
            "explicit key": "? a\n",
            "nested dash": "key:\n  - - a\n",
            "two spaces after dash": "key:\n  -  a\n",
            "mapping without space": "key:value\n",
            "empty document": "# only a comment\n",
        }
        for name, text in cases.items():
            with self.subTest(name):
                with self.assertRaises(ContractError):
                    parse_yaml_subset(text)


class ContractFileTests(unittest.TestCase):
    def setUp(self) -> None:
        self.contract = load_contract(CONTRACT)
        self.by_id = {check.id: check for check in self.contract.checks}

    def test_paid_inference_endpoints_match_the_live_rule(self) -> None:
        for check_id, path, rule in (
            ("inference-completions", "/v1/completions", "6babfd10032746f7863cda066d95125d"),
            ("inference-responses", "/v1/responses", "6babfd10032746f7863cda066d95125d"),
            ("inference-chat", "/v1/chat/completions", "41cee0f88822411baf864bb54e8b4727"),
        ):
            with self.subTest(check_id):
                check = self.by_id[check_id]
                self.assertEqual((check.cls, check.host, check.path), ("paid", "inference.a-11-oy.com", path))
                self.assertEqual(check.methods, ("GET", "POST"))
                self.assertEqual((check.rule_id, check.price_atomic), (rule, 20000))
        self.assertEqual(
            (self.contract.terms.scheme, self.contract.terms.network, self.contract.terms.x402_version),
            ("exact", "eip155:8453", 2),
        )
        self.assertEqual(self.contract.terms.pay_to, PAY_TO)
        self.assertEqual(self.contract.terms.asset, USDC_BASE)

    def test_internal_vllm_paths_must_be_refused(self) -> None:
        internal = {(c.host, c.path) for c in self.contract.checks if c.cls == "internal"}
        self.assertEqual(
            internal,
            {("inference.a-11-oy.com", path) for path in ("/metrics", "/docs", "/openapi.json", "/redoc")},
        )

    def test_owner_free_surfaces_are_declared_free(self) -> None:
        free = {(c.host, c.path) for c in self.contract.checks if c.cls == "free"}
        required = {
            ("a-11-oy.com", "/"),
            ("a-11-oy.com", "/pricing"),
            ("a-11-oy.com", "/healthz"),
            ("a-11-oy.com", "/robots.txt"),
            ("a-11-oy.com", "/.well-known/security.txt"),
            ("www.a-11-oy.com", "/"),
            ("holdings.a-11-oy.com", "/"),
            ("a11oy.net", "/"),
            ("agents-store.a-11-oy.com", "/healthz"),
            ("mcp.a-11-oy.com", "/"),
            ("mcp.a-11-oy.com", "/healthz"),
            ("mcp.a-11-oy.com", "/.well-known/mcp/server-card.json"),
            ("ntfy.a11oy.net", "/"),
        }
        self.assertLessEqual(required, free)
        for check in self.contract.checks:
            if check.cls == "free":
                self.assertEqual(check.accept, ("ok", "redirect", "origin-auth"), check.id)

    def test_every_host_is_in_an_estate_zone_and_probed_without_exempt_agents(self) -> None:
        for check in self.contract.checks:
            self.assertTrue(
                check.host in ("a-11-oy.com", "a11oy.net") or check.host.endswith((".a-11-oy.com", ".a11oy.net")),
                check.host,
            )
        agent = self.contract.client.user_agent.lower()
        for substring in self.contract.client.exempt_user_agent_substrings:
            self.assertNotIn(substring.lower(), agent)
        self.assertEqual(self.contract.client.post_body, "{}")

    def test_sha256_identifies_the_exact_contract_bytes(self) -> None:
        self.assertEqual(self.contract.sha256, hashlib.sha256(CONTRACT.read_bytes()).hexdigest())


class ContractValidationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.source = CONTRACT.read_text(encoding="utf-8")

    def assert_invalid(self, text: str, fragment: str) -> None:
        path = Path(self.tmp.name) / "contract.yaml"
        path.write_text(text, encoding="utf-8")
        with self.assertRaises(ContractError) as raised:
            load_contract(path)
        self.assertIn(fragment, str(raised.exception))

    def replace_once(self, old: str, new: str) -> str:
        self.assertEqual(self.source.count(old), 1, old)
        return self.source.replace(old, new)

    def test_user_agent_with_an_exempt_substring_is_rejected(self) -> None:
        self.assert_invalid(
            self.replace_once(
                'user_agent: "szl-edge-contract/1 (+https://github.com/szl-holdings/szl-org-health)"',
                'user_agent: "szl-readiness-probe/1"',
            ),
            "paywall-exempt substring 'szl-readiness'",
        )

    def test_paid_check_without_rule_or_with_a_wrong_price_is_rejected(self) -> None:
        self.assert_invalid(
            self.replace_once(
                '    rule_id: "41cee0f88822411baf864bb54e8b4727"\n    price_atomic: 20000\n',
                '    rule_id: "41cee0f88822411baf864bb54e8b4727"\n    price_atomic: 30000\n',
            ),
            "differs from the inventory price 20000",
        )
        self.assert_invalid(
            self.replace_once(
                '    rule_id: "41cee0f88822411baf864bb54e8b4727"\n    price_atomic: 20000\n', ""
            ),
            "rule_id must be a non-empty string",
        )

    def test_verified_bot_rules_cannot_back_a_paid_probe(self) -> None:
        self.assert_invalid(
            self.replace_once(
                '    rule_id: "41cee0f88822411baf864bb54e8b4727"\n    price_atomic: 20000\n',
                '    rule_id: "b8026fdb4f0d42c6ba734ddd77e75644"\n    price_atomic: 25000\n',
            ),
            "charges verified bots only",
        )

    def test_every_enabled_rule_is_probed_or_explained(self) -> None:
        self.assert_invalid(
            self.replace_once(
                '  - rule_id: "b8026fdb4f0d42c6ba734ddd77e75644"\n'
                '    reason: "Charges verified bots only (cf.client.bot); not observable from an unverified runner."\n',
                "",
            ),
            "neither probed by a paid check nor listed in unprobed_rules",
        )

    def test_closed_schema_and_unique_ids(self) -> None:
        self.assert_invalid(self.source + "surprise: true\n", "unknown keys: surprise")
        self.assert_invalid(
            self.replace_once("  - id: apex-pricing\n", "  - id: apex-root\n"),
            "duplicate check ids: apex-root",
        )
        self.assert_invalid(
            self.replace_once("    path: /pricing\n", "    path: /\n"),
            "same host and path",
        )
        self.assert_invalid(
            self.replace_once("schema: szl.edge-contract/v1\n", "schema: szl.edge-contract/v2\n"),
            "schema must be",
        )

    def test_free_and_internal_checks_cannot_accept_a_paywall(self) -> None:
        self.assert_invalid(
            self.replace_once(
                "    path: /pricing\n    methods: [GET]\n",
                "    path: /pricing\n    methods: [GET]\n    accept: [ok, paywall]\n",
            ),
            "refused ['paywall']",
        )

    def test_accept_cannot_add_outcomes_forbidden_for_the_class(self) -> None:
        for outcome in ("payment-unparsed", "challenge"):
            self.assert_invalid(
                self.replace_once(
                    "    path: /pricing\n    methods: [GET]\n",
                    f"    path: /pricing\n    methods: [GET]\n    accept: [ok, {outcome}]\n",
                ),
                f"refused ['{outcome}']",
            )
        self.assert_invalid(
            self.replace_once(
                "    path: /metrics\n    methods: [GET]\n",
                "    path: /metrics\n    methods: [GET]\n    accept: [edge-block, challenge]\n",
            ),
            "can only narrow the internal defaults",
        )
        narrowed = self.replace_once(
            "    path: /pricing\n    methods: [GET]\n",
            "    path: /pricing\n    methods: [GET]\n    accept: [ok]\n",
        )
        path = Path(self.tmp.name) / "narrow.yaml"
        path.write_text(narrowed, encoding="utf-8")
        pricing = next(check for check in load_contract(path).checks if check.id == "apex-pricing")
        self.assertEqual(pricing.accept, ("ok",))

    def test_forbidden_outcomes_never_pass_when_named_in_accept(self) -> None:
        terms = PaymentTerms(2, "exact", "eip155:8453", USDC_BASE, PAY_TO)
        free = Check(
            "free-widened",
            "free",
            "a-11-oy.com",
            "/pricing",
            ("GET",),
            "test",
            ("ok", "payment-unparsed", "challenge"),
        )
        internal = Check(
            "internal-widened",
            "internal",
            "inference.a-11-oy.com",
            "/metrics",
            ("GET",),
            "test",
            ("edge-block", "challenge", "payment-unparsed"),
        )
        unparsed = Observation(402, {}, b"pay")
        challenged = Observation(403, {"cf-mitigated": ["challenge"]}, b"")
        blocked = Observation(403, {}, b"Sorry, you have been blocked")
        for check, observation in (
            (free, unparsed),
            (free, challenged),
            (internal, unparsed),
            (internal, challenged),
        ):
            row = evaluate(check, "GET", observation, terms)
            self.assertEqual(row["verdict"], "FAIL", row["message"])
        passed = evaluate(internal, "GET", blocked, terms)
        self.assertEqual((passed["verdict"], passed["outcome"]), ("PASS", "edge-block"))

    def test_only_get_and_post_are_supported(self) -> None:
        self.assert_invalid(
            self.replace_once("    path: /pricing\n    methods: [GET]\n", "    path: /pricing\n    methods: [PUT]\n"),
            "method 'PUT' is not one of GET, POST",
        )


class PaymentHeaderTests(unittest.TestCase):
    URL = "https://inference.a-11-oy.com/v1/completions"

    def test_decodes_the_recorded_x402_v2_header(self) -> None:
        # The exact PAYMENT-REQUIRED value of Cloudflare URL Scanner scan
        # ab7465a9 (GET https://inference.a-11-oy.com/v1/completions, 16:34Z).
        recorded = (
            "eyJ4NDAyVmVyc2lvbiI6MiwiZXJyb3IiOiJQQVlNRU5ULVNJR05BVFVSRSBoZWFkZXIgaXMgcmVxdWlyZWQiLCJyZXNvdXJjZSI6"
            "eyJ1cmwiOiJodHRwczovL2luZmVyZW5jZS5hLTExLW95LmNvbS92MS9jb21wbGV0aW9ucyJ9LCJhY2NlcHRzIjpbeyJzY2hlbWUi"
            "OiJleGFjdCIsIm5ldHdvcmsiOiJlaXAxNTU6ODQ1MyIsImFtb3VudCI6IjIwMDAwIiwiYXNzZXQiOiIweDgzMzU4OWZDRDZlRGI2"
            "RTA4ZjRjN0MzMkQ0ZjcxYjU0YmRBMDI5MTMiLCJwYXlUbyI6IjB4NTBFOUIzMzVhYzIzM2ZjYzVlODc0MDQzNjdFN0RlMjUzQTYz"
            "RDQ2MCIsIm1heFRpbWVvdXRTZWNvbmRzIjozNjAwLCJleHRyYSI6eyJuYW1lIjoiVVNEIENvaW4iLCJ2ZXJzaW9uIjoiMiJ9fV19"
        )
        decoded, problem = decode_payment_required([recorded])
        self.assertEqual(problem, "")
        self.assertEqual(decoded["x402_version"], 2)
        self.assertEqual(decoded["resource_url"], self.URL)
        self.assertEqual(
            decoded["offers"],
            [{"amount": 20000, "scheme": "exact", "network": "eip155:8453", "asset": USDC_BASE, "pay_to": PAY_TO}],
        )

    def test_malformed_headers_are_not_a_paywall(self) -> None:
        cases = {
            "missing": [],
            "duplicate": [payment_header(self.URL), payment_header(self.URL)],
            "not base64": ["%%%not-base64%%%"],
            "not json": [base64.b64encode(b"not json").decode()],
            "no accepts": [base64.b64encode(json.dumps({"x402Version": 2, "accepts": []}).encode()).decode()],
            "numeric amount": [
                base64.b64encode(
                    json.dumps({"x402Version": 2, "accepts": [{"amount": 20000, "scheme": "exact"}]}).encode()
                ).decode()
            ],
            "too long": ["A" * 20000],
        }
        for name, values in cases.items():
            with self.subTest(name):
                decoded, problem = decode_payment_required(values)
                self.assertIsNone(decoded)
                self.assertTrue(problem)

    def test_classification_distinguishes_edge_outcomes(self) -> None:
        def observe(spec: dict) -> Observation:
            headers: dict[str, list[str]] = {}
            for name, value in spec.get("headers", []):
                headers.setdefault(name.lower(), []).append(value)
            return Observation(status=spec["status"], headers=headers, body=spec.get("body", b""))

        cases = [
            (paywall(self.URL), "paywall"),
            ({"status": 402, "headers": [], "body": b"pay"}, "payment-unparsed"),
            (challenge(), "challenge"),
            ({"status": 403, "headers": [], "body": b"<script>window._cf_chl_opt={}</script>"}, "challenge"),
            (edge_block(), "edge-block"),
            ({"status": 403, "headers": [], "body": b"<title>Attention Required! | Cloudflare</title>"}, "edge-block"),
            # 2026-11-14: the WAF block page embeds the challenge-platform
            # script, so the script alone is not a challenge marker.
            (
                {
                    "status": 403,
                    "headers": [("Content-Type", "text/html")],
                    "body": b'<title>Attention Required! | Cloudflare</title><script src="/cdn-cgi/challenge-platform/hg/pat/vscript.js"></script>',
                },
                "edge-block",
            ),
            (
                {"status": 403, "headers": [], "body": b'<script src="/cdn-cgi/challenge-platform/instrument.js"></script>'},
                "origin-auth",
            ),
            (access_refusal(), "access-denied"),
            (
                {"status": 302, "headers": [("Location", "https://team.cloudflareaccess.com/cdn-cgi/access/login/x")]},
                "access-denied",
            ),
            (origin_json(403), "origin-auth"),
            (origin_json(401), "origin-auth"),
            (cloudflare_502(), "origin-5xx"),
            ({"status": 500, "headers": [], "body": b"boom"}, "origin-5xx"),
            (ok(), "ok"),
            (redirect("https://a-11-oy.com/"), "redirect"),
            ({"status": 404, "headers": [], "body": b""}, "not-found"),
            (validation_error(), "client-error"),
        ]
        for spec, expected in cases:
            with self.subTest(expected=expected, status=spec["status"]):
                self.assertEqual(classify(observe(spec))[0], expected)
        self.assertEqual(classify(Observation(status=None, error="ConnectionRefusedError"))[0], "transport-error")

    def test_connect_to_accepts_loopback_only(self) -> None:
        self.assertEqual(parse_connect_to("127.0.0.1:8080"), ("127.0.0.1", 8080))
        self.assertEqual(parse_connect_to("[::1]:9"), ("::1", 9))
        for value in ("10.0.0.1:80", "example.com:443", "127.0.0.1", "127.0.0.1:0", "127.0.0.1:x"):
            with self.subTest(value), self.assertRaises(ContractError):
                parse_connect_to(value)


class LiveShapeRunTests(_ContractRun):
    def test_an_edge_that_honours_the_contract_passes_every_request(self) -> None:
        code, receipt, stub, output = self.run_checker(intended_edge(self.contract))
        self.assertEqual(code, 0, output)
        self.assertEqual(receipt["verdict"], "PASS")
        expected_requests = sum(len(check.methods) for check in self.contract.checks)
        self.assertEqual(receipt["summary"], {
            "requests": expected_requests, "passed": expected_requests, "failed": 0, "failed_by_label": {},
        })
        self.assertEqual(receipt["transport"], "loopback-override")
        self.assertEqual(receipt["contract"]["sha256"], self.contract.sha256)
        self.assertEqual(len(stub.requests), expected_requests)
        for request in stub.requests:
            self.assertEqual(request["headers"].get("User-Agent"), self.contract.client.user_agent)
            self.assertNotIn("Authorization", request["headers"])
            self.assertNotIn("Cookie", request["headers"])
            if request["method"] == "POST":
                self.assertEqual(request["body"], b"{}")
                self.assertEqual(request["headers"].get("Content-Type"), "application/json")
        hosts = {request["host"] for request in stub.requests}
        self.assertEqual(hosts, {check.host for check in self.contract.checks})
        paid = self.rows(receipt, "inference-completions")
        self.assertEqual(set(paid), {"GET", "POST"})
        self.assertIn("amount 20000 = rule 6babfd10032746f7863cda066d95125d price", paid["POST"]["message"])
        self.assertEqual(paid["GET"]["observed"]["x402"]["offers"][0]["amount"], 20000)
        self.assertEqual(paid["GET"]["observed"]["cf_origin_ms"], 0.0)
        sidecar = Path(str(self.receipt_path) + ".sha256").read_text(encoding="ascii")
        digest = hashlib.sha256(self.receipt_path.read_bytes()).hexdigest()
        self.assertEqual(sidecar, f"{digest}  receipt.json\n")

    def test_post_that_reaches_the_origin_unpaid_is_a_violation(self) -> None:
        routes = intended_edge(self.contract)
        for check in self.contract.checks:
            if check.cls == "paid":
                routes[(check.host, "POST", check.path)] = validation_error()
        code, receipt, _, output = self.run_checker(routes)
        self.assertEqual(code, 1)
        self.assertEqual(receipt["summary"]["failed"], 3)
        self.assertEqual(receipt["summary"]["failed_by_label"], {"4xx": 3})
        for check_id in ("inference-completions", "inference-responses", "inference-chat"):
            rows = self.rows(receipt, check_id)
            self.assertEqual(rows["GET"]["verdict"], "PASS")
            self.assertEqual(rows["POST"]["verdict"], "FAIL")
            self.assertIn("POST reached the origin unpaid (HTTP 422)", rows["POST"]["message"])
        self.assertIn("FAIL  paid", output)

    def test_free_surface_charged_again_is_a_402_paywall_violation(self) -> None:
        routes = intended_edge(self.contract)
        routes[("a-11-oy.com", "GET", "/")] = paywall("https://a-11-oy.com/", amount=100000)
        code, receipt, _, _ = self.run_checker(routes)
        self.assertEqual(code, 1)
        row = self.rows(receipt, "apex-root")["GET"]
        self.assertEqual((row["verdict"], row["label"]), ("FAIL", "402-paywall"))
        self.assertIn("charged 100000 atomic units", row["message"])

    def test_paid_terms_must_match_the_rule(self) -> None:
        url = "https://inference.a-11-oy.com/v1/completions"
        variants = {
            "amount": (paywall(url, amount=100000), "amount 100000 != rule 6babfd10032746f7863cda066d95125d price 20000"),
            "pay_to": (paywall(url, offer={"payTo": "0x" + "1" * 40}), "no offer with scheme exact"),
            "network": (paywall(url, offer={"network": "eip155:1"}), "no offer with scheme exact"),
            "resource": (paywall(url, resource_url="https://evil.example/v1/completions"), "resource.url"),
            "version": (paywall(url, version=1), "x402Version 1 != 2"),
            "no header": ({"status": 402, "headers": [], "body": b"pay"}, "402-unparsed"),
        }
        for name, (spec, fragment) in variants.items():
            with self.subTest(name):
                routes = intended_edge(self.contract)
                routes[("inference.a-11-oy.com", "GET", "/v1/completions")] = spec
                code, receipt, _, _ = self.run_checker(routes, "--only", "inference-completions")
                self.assertEqual(code, 1)
                self.assertEqual(receipt["selection"], "subset")
                row = self.rows(receipt, "inference-completions")["GET"]
                self.assertEqual(row["verdict"], "FAIL")
                self.assertIn(fragment, row["message"])
                self.assertEqual(self.rows(receipt, "inference-completions")["POST"]["verdict"], "PASS")

    def test_challenges_are_named_and_never_pass(self) -> None:
        routes = intended_edge(self.contract)
        routes[("a11oy.net", "GET", "/")] = challenge()
        routes[("inference.a-11-oy.com", "GET", "/v1/responses")] = challenge()
        routes[("inference.a-11-oy.com", "GET", "/metrics")] = challenge()
        code, receipt, _, _ = self.run_checker(routes)
        self.assertEqual(code, 1)
        self.assertEqual(receipt["summary"]["failed_by_label"], {"403-challenge": 3})
        self.assertIn("bot protection, not the paywall", self.rows(receipt, "proof-root")["GET"]["message"])
        self.assertIn("instead of answering 402", self.rows(receipt, "inference-responses")["GET"]["message"])
        self.assertIn("a managed challenge is not a block", self.rows(receipt, "inference-metrics")["GET"]["message"])

    def test_internal_paths_must_be_refused(self) -> None:
        routes = intended_edge(self.contract)
        routes[("inference.a-11-oy.com", "GET", "/metrics")] = ok("vllm metrics")
        routes[("inference.a-11-oy.com", "GET", "/docs")] = {"status": 404, "headers": [], "body": b""}
        routes[("inference.a-11-oy.com", "GET", "/openapi.json")] = access_refusal()
        routes[("inference.a-11-oy.com", "GET", "/redoc")] = origin_json(403)
        code, receipt, _, _ = self.run_checker(routes)
        self.assertEqual(code, 1)
        self.assertIn("internal path is served", self.rows(receipt, "inference-metrics")["GET"]["message"])
        self.assertEqual(self.rows(receipt, "inference-docs")["GET"]["verdict"], "FAIL")
        self.assertEqual(self.rows(receipt, "inference-openapi")["GET"]["verdict"], "PASS")
        self.assertEqual(self.rows(receipt, "inference-redoc")["GET"]["verdict"], "PASS")

    def test_origin_failures_and_access_walls_are_distinguished_on_free_surfaces(self) -> None:
        routes = intended_edge(self.contract)
        routes[("holdings.a-11-oy.com", "GET", "/")] = cloudflare_502()
        routes[("agents-store.a-11-oy.com", "GET", "/healthz")] = {
            "status": 302,
            "headers": [("Location", "https://team.cloudflareaccess.com/cdn-cgi/access/login/agents-store")],
        }
        code, receipt, _, _ = self.run_checker(routes)
        self.assertEqual(code, 1)
        holdings = self.rows(receipt, "holdings-root")["GET"]
        self.assertEqual(holdings["label"], "5xx-origin")
        self.assertIn("Cloudflare error page", holdings["message"])
        self.assertIn("not a paywall decision", holdings["message"])
        self.assertEqual(self.rows(receipt, "agents-store-healthz")["GET"]["label"], "302-access")

    def test_unreachable_edge_is_a_transport_error_violation(self) -> None:
        with socket.socket() as probe:
            probe.bind(("127.0.0.1", 0))
            closed_port = probe.getsockname()[1]
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            code = main(
                [
                    "--contract", str(CONTRACT),
                    "--receipt", str(self.receipt_path),
                    "--connect-to", f"127.0.0.1:{closed_port}",
                    "--only", "apex-root",
                ]
            )
        self.assertEqual(code, 1)
        receipt = json.loads(self.receipt_path.read_text(encoding="utf-8"))
        row = self.rows(receipt, "apex-root")["GET"]
        self.assertEqual((row["label"], row["status"]), ("transport-error", None))

    def test_step_summary_lists_failures_first(self) -> None:
        summary = Path(self.tmp.name) / "summary.md"
        os.environ["GITHUB_STEP_SUMMARY"] = str(summary)
        routes = intended_edge(self.contract)
        routes[("ntfy.a11oy.net", "GET", "/")] = paywall("https://ntfy.a11oy.net/", amount=1000000)
        code, _, _, _ = self.run_checker(routes)
        self.assertEqual(code, 1)
        text = summary.read_text(encoding="utf-8")
        self.assertTrue(text.startswith("## Edge contract: FAIL\n"))
        table = [line for line in text.splitlines() if line.startswith("| ")]
        self.assertEqual(table[0], "| Verdict | Method | URL | Status | Message |")
        self.assertTrue(table[1].startswith("| FAIL | GET | https://ntfy.a11oy.net/ | 402 | 402-paywall"), table[1])
        self.assertTrue(all(row.startswith("| PASS |") for row in table[2:]))

    def test_invalid_contract_or_unknown_check_exits_2_without_a_receipt(self) -> None:
        bad = Path(self.tmp.name) / "bad.yaml"
        bad.write_text("schema: wrong\n", encoding="utf-8")
        err = io.StringIO()
        with redirect_stderr(err):
            self.assertEqual(main(["--contract", str(bad), "--receipt", str(self.receipt_path)]), 2)
            self.assertEqual(
                main(["--contract", str(CONTRACT), "--receipt", str(self.receipt_path), "--only", "nope"]), 2
            )
            self.assertEqual(
                main(["--contract", str(CONTRACT), "--receipt", str(self.receipt_path), "--connect-to", "8.8.8.8:53"]),
                2,
            )
        self.assertFalse(self.receipt_path.exists())
        self.assertIn("edge contract invalid", err.getvalue())


class WorkflowContractTests(unittest.TestCase):
    def test_workflow_is_scheduled_unprivileged_and_pinned(self) -> None:
        source = WORKFLOW.read_text(encoding="utf-8")
        events, crons = _canonical_triggers(source, WORKFLOW.name)
        self.assertEqual(events, ("schedule", "workflow_dispatch"))
        self.assertEqual(len(crons), 1)
        self.assertRegex(crons[0], r"^\d{1,2} \*/6 \* \* \*$")
        self.assertFalse(_uses_actions_secrets(source), "the edge contract needs no secrets")
        self.assertIn("\npermissions:\n  contents: read\n\n", source)
        self.assertNotRegex(source, r":\s*write\b")
        self.assertNotIn("write-all", source)
        self.assertNotIn("continue-on-error", source)
        self.assertNotIn("|| true", source)
        self.assertIn("persist-credentials: false", source)
        uses = re.findall(r"(?m)^\s+uses:\s*(\S+)", source)
        self.assertTrue(uses)
        for reference in uses:
            self.assertRegex(reference, r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+@[0-9a-f]{40}$")
        self.assertIn(
            "run: python -I -B edge/check_contract.py --contract edge/contract.yaml "
            "--receipt reports/edge-contract-receipt.json",
            source,
        )
        upload = source.split("- name: Upload the edge contract receipt", 1)[1]
        self.assertIn("if: always()", upload)
        self.assertIn("if-no-files-found: error", upload)


if __name__ == "__main__":
    unittest.main(verbosity=2)
