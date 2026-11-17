#!/usr/bin/env python3
"""SZL Org Health — live schema-v2 estate census and HTTP service."""
from __future__ import annotations

import json
import os
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from census import SCHEMA_VERSION, build_report
from census.common import resolve_txt as _resolve_txt
from census.portal_projection import project_portal_index
from census.proof_graph import project_proof_graph
from census.sites import DOMAINS


class ReportUnavailable(Exception):
    """No fresh public response is available within the HTTP work budget."""


class PublicResponses:
    """One background collection; HTTP callers never wait on provider I/O.

    Expired data is not served. Failures back off for a full refresh interval,
    and timestamps/UNKNOWN states come from the collectors without alteration.
    """

    def __init__(self):
        self._lock = threading.Lock()
        self._responses = {}
        self._expires_at = 0.0
        self._retry_at = 0.0
        self._refreshing = False

    def get(self, path: str) -> bytes:
        with self._lock:
            now = time.monotonic()
            if self._responses and now < self._expires_at:
                # Optional graph failure cannot produce a 500 on a cache miss.
                payload = self._responses.get(path)
                if payload is not None:
                    return payload
                raise ReportUnavailable
            if not self._refreshing and now >= self._retry_at:
                self._refreshing = True
                try:
                    threading.Thread(target=self._refresh, daemon=True).start()
                except Exception:
                    self._refreshing = False
                    self._retry_at = now + 60
            # No queued refresh, future.result(), or provider work in handlers.
            raise ReportUnavailable

    def _refresh(self):
        responses = None
        try:
            report = build_report(exposure="public", use_cache=False)
            portal = project_portal_index(report)
            responses = {
                path: json.dumps(value, separators=(",", ":"), allow_nan=False).encode()
                for path, value in (("/api/health", report), ("/api/portal", portal))
            }
            try:
                # A new optional graph projection must not poison the existing
                # health/portal readbacks when its own contract is unavailable.
                proof_graph = project_proof_graph(report)
                responses["/api/proof-graph"] = json.dumps(
                    proof_graph, separators=(",", ":"), allow_nan=False
                ).encode()
            except Exception:
                # Do not reveal upstream details or serve a stale graph.
                # Missing optional entry becomes a bounded HTTP 503.
                pass
        except Exception:
            # Do not expose provider exceptions or promote an old result.
            pass
        finally:
            with self._lock:
                finished = time.monotonic()
                if responses is not None:
                    self._responses = responses
                    self._expires_at = finished + 60
                self._retry_at = finished + 60
                self._refreshing = False


PUBLIC_RESPONSES = PublicResponses()


class BoundedHTTPServer(ThreadingHTTPServer):
    """Bound request threads before creating them; no overflow work queue."""

    daemon_threads = True
    max_handlers = 8
    socket_timeout = 5.0

    def __init__(self, *args, **kwargs):
        self._slots = threading.BoundedSemaphore(self.max_handlers)
        super().__init__(*args, **kwargs)

    def get_request(self):
        request, address = super().get_request()
        request.settimeout(self.socket_timeout)
        return request, address

    def process_request(self, request, client_address):
        if not self._slots.acquire(blocking=False):
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except BaseException:
            self._slots.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self._slots.release()


def collect_dns():
    """Compatibility wrapper preserving the original patchable DNS contract."""
    out = {}
    for domain in DOMAINS:
        spf = _resolve_txt(domain)
        dmarc = _resolve_txt(f"_dmarc.{domain}")
        out[domain] = {
            "spf": None if spf is None else "v=spf1" in spf.lower(),
            "dmarc": None if dmarc is None else "v=dmarc1" in dmarc.lower(),
            "dmarc_reject": None
            if dmarc is None
            else "p=reject" in dmarc.lower(),
        }
    return out


class Handler(BaseHTTPRequestHandler):
    server_version = "szl-org-health"

    def _send(self, code: int, body: str | bytes, ctype: str = "application/json"):
        payload = body if isinstance(body, bytes) else body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        if code == 503:
            self.send_header("Retry-After", "60")
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self):  # noqa: N802 - BaseHTTPRequestHandler API
        path = self.path.split("?", 1)[0]
        if path in ("/api/health", "/api/portal", "/api/proof-graph"):
            try:
                payload = PUBLIC_RESPONSES.get(path)
            except ReportUnavailable:
                self._send(503, '{"error":"UNAVAILABLE"}')
            else:
                self._send(200, payload)
        elif path in ("/proof-graph", "/proof-graph.html"):
            try:
                with open("static/proof-graph.html", "rb") as source:
                    self._send(200, source.read(), "text/html; charset=utf-8")
            except FileNotFoundError:
                self._send(404, "not found", "text/plain; charset=utf-8")
        elif path in ("/", "/index.html"):
            try:
                with open("static/index.html", "rb") as source:
                    self._send(200, source.read(), "text/html; charset=utf-8")
            except FileNotFoundError:
                self._send(404, "not found", "text/plain; charset=utf-8")
        elif path == "/healthz":
            self._send(
                200,
                json.dumps(
                    {
                        "status": "ok",
                        "service": "szl-org-health",
                        "schema_version": SCHEMA_VERSION,
                    },
                    separators=(",", ":"),
                ),
            )
        else:
            self._send(404, "not found", "text/plain; charset=utf-8")

    def log_message(self, *_args):
        pass


def main() -> None:
    port = int(os.environ.get("PORT", "7860"))
    server = BoundedHTTPServer(("0.0.0.0", port), Handler)
    print(f"szl-org-health serving on 0.0.0.0:{port}", flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
