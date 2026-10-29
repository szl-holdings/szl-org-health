from __future__ import annotations

import json
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from tools.web_evidence import CrawlPolicy, PolicyError, WebEvidenceCollector


class _FixtureHandler(BaseHTTPRequestHandler):
    def do_GET(self):  # noqa: N802 - BaseHTTPRequestHandler API
        if self.path == "/robots.txt":
            body = b"User-agent: *\nDisallow: /private\nCrawl-delay: 0\n"
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
        elif self.path == "/page":
            body = (
                b"<!doctype html><html><head><title>Public fixture</title>"
                b"<script>ignore()</script></head><body><h1>Hello</h1>"
                b"<p>Evidence text.</p><a href='/next'>next</a></body></html>"
            )
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
        elif self.path == "/private":
            body = b"<html><body>must not be fetched</body></html>"
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
        elif self.path == "/huge":
            body = b"x" * 512
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
        elif self.path == "/error":
            body = b"temporary failure"
            self.send_response(503)
            self.send_header("Content-Type", "text/plain")
        else:
            body = b"not found"
            self.send_response(404)
            self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args):
        pass


class WebEvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), _FixtureHandler)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.base = f"http://127.0.0.1:{cls.server.server_port}"

    @classmethod
    def tearDownClass(cls) -> None:
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=2)

    def collector(self, **kwargs) -> WebEvidenceCollector:
        policy = CrawlPolicy(
            allowed_hosts=frozenset({"127.0.0.1"}),
            allow_private_network=True,
            min_delay_seconds=0,
            max_retries=0,
            **kwargs,
        )
        return WebEvidenceCollector(policy)

    def test_measured_receipt_is_bounded_and_hashed(self) -> None:
        receipt = self.collector(include_text=True).fetch(self.base + "/page")
        self.assertEqual(receipt.state, "MEASURED")
        self.assertEqual(receipt.evidence_class, "MEASURED")
        self.assertEqual(receipt.status, 200)
        self.assertEqual(receipt.title, "Public fixture")
        self.assertIn("Evidence text.", receipt.text or "")
        self.assertNotIn("ignore()", receipt.text or "")
        self.assertEqual(receipt.link_count, 1)
        self.assertEqual(len(receipt.body_sha256 or ""), 64)
        self.assertEqual(len(receipt.text_sha256 or ""), 64)
        self.assertEqual(json.loads(json.dumps(receipt.as_dict()))["state"], "MEASURED")

    def test_robots_disallow_is_blocked_without_fetching_page(self) -> None:
        receipt = self.collector().fetch(self.base + "/private")
        self.assertEqual(receipt.state, "BLOCKED")
        self.assertEqual(receipt.reason, "ROBOTS_DISALLOW")
        self.assertFalse(receipt.robots_allowed)
        self.assertIsNone(receipt.body_sha256)

    def test_response_budget_is_blocked(self) -> None:
        receipt = self.collector(max_bytes_per_response=100).fetch(self.base + "/huge")
        self.assertEqual(receipt.state, "BLOCKED")
        self.assertEqual(receipt.reason, "RESPONSE_BYTE_LIMIT")
        self.assertEqual(receipt.bytes_read, 0)

    def test_total_budget_includes_robots_bytes(self) -> None:
        receipt = self.collector(max_total_bytes=10_000).fetch(self.base + "/page")
        self.assertEqual(receipt.state, "MEASURED")
        self.assertGreater(receipt.bytes_read, 0)
        tiny = self.collector(max_total_bytes=10).fetch(self.base + "/page")
        self.assertEqual(tiny.state, "BLOCKED")
        self.assertEqual(tiny.reason, "TOTAL_BYTE_LIMIT")

    def test_http_unavailable_is_not_green(self) -> None:
        receipt = self.collector().fetch(self.base + "/error")
        self.assertEqual(receipt.state, "UNAVAILABLE")
        self.assertEqual(receipt.evidence_class, "UNAVAILABLE")
        self.assertEqual(receipt.status, 503)

    def test_ssrf_and_allowlist_guards_fail_closed(self) -> None:
        blocked = self.collector().fetch("http://127.0.0.2/private")
        self.assertEqual(blocked.state, "BLOCKED")
        self.assertEqual(blocked.reason, "HOST_NOT_ALLOWLISTED")
        with self.assertRaises(PolicyError):
            CrawlPolicy(allowed_hosts=frozenset())

    def test_collection_deduplicates_and_bounds_urls(self) -> None:
        receipts = self.collector().collect([self.base + "/page", self.base + "/page", "# comment"])
        self.assertEqual(len(receipts), 1)
        with self.assertRaises(PolicyError):
            self.collector(max_urls=1).collect([self.base + "/page", self.base + "/error"])

    def test_no_private_network_by_default(self) -> None:
        policy = CrawlPolicy(allowed_hosts=frozenset({"127.0.0.1"}), min_delay_seconds=0, max_retries=0)
        receipt = WebEvidenceCollector(policy).fetch(self.base + "/page")
        self.assertEqual(receipt.state, "BLOCKED")
        self.assertEqual(receipt.reason, "PRIVATE_NETWORK_TARGET")


if __name__ == "__main__":
    unittest.main()
