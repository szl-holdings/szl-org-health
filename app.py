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
from census.system_design import project_system_design, render_html as render_system_design
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
                # Optional source-only architecture research must not poison
                # proven existing health/portal/proof-graph responses.
                design = project_system_design(portal)
                responses["/api/system-design"] = json.dumps(
                    design, separators=(",", ":"), allow_nan=False
                ).encode()
                responses["/system-design"] = render_system_design(design)
            except Exception:
                # Do not reveal upstream details or serve a stale map.
                # Missing optional entry keeps the proven endpoints authoritative.
                pass
            try:
                # A new optional graph projection must not poison the existing
                # health/portal readbacks when internal graph collectors fail-closed.
                proof_graph = project_proof_graph(report)
                responses["/api/proof-graph"] = json.dumps(
                    proof_graph, separators=(",", ":"), allow_nan=False
                ).encode()
            except Exception:
                pass
        except Exception:
            responses = None
        finally:
            with self._lock:
                self._refreshing = False
                now = time.monotonic()
                if responses:
                    self._responses = responses
                    self._expires_at = now + 120.0
                    self._retry_at = now
                else:
                    self._retry_at = now + 30.0


PUBLIC_RESPONSES = PublicResponses()


class HealthHandler(BaseHTTPRequestHandler):
    """Fail-closed HTTP handler serving verified estate telemetry."""

    server_version = "SZLOrgHealth/2.0"

    def do_GET(self) -> None:
        path = self.path.split("?", 1)[0]
        if path == "/":
            self.send_response(302)
            self.send_header("Location", "/api/health")
            self.end_headers()
            return

        if path not in (
            "/api/health",
            "/api/portal",
            "/api/system-design",
            "/api/proof-graph",
            "/system-design",
            "/healthz",
            "/robots.txt",
            "/dns-query",
        ):
            self.send_response(404)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.end_headers()
            self.wfile.write(b"404 not found")
            return

        if path == "/healthz":
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.end_headers()
            self.wfile.write(b"ok")
            return

        if path == "/robots.txt":
            body = b"User-agent: *\nDisallow: /\n"
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return

        if path == "/dns-query":
            qname = ""
            if "?" in self.path:
                for part in self.path.split("?", 1)[1].split("&"):
                    if part.startswith("name="):
                        qname = part[5:]
            if not qname:
                self.send_response(400)
                self.send_header("Content-Type", "text/plain; charset=utf-8")
                self.end_headers()
                self.wfile.write(b"missing name parameter")
                return
            answers = _resolve_txt(qname)
            body = json.dumps({"name": qname, "answers": answers}, separators=(",", ":")).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return

        try:
            payload = PUBLIC_RESPONSES.get(path)
            content_type = (
                "text/html; charset=utf-8"
                if path == "/system-design"
                else "application/json; charset=utf-8"
            )
            self.send_response(200)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)
        except ReportUnavailable:
            self.send_response(503)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.end_headers()
            self.wfile.write(b"503 service unavailable: report compiling")
        except Exception:
            self.send_response(500)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.end_headers()
            self.wfile.write(b"500 internal server error")

    def log_message(self, format: str, *args) -> None:
        pass


def run() -> None:
    port = int(os.environ.get("PORT", "8080"))
    server = ThreadingHTTPServer(("0.0.0.0", port), HealthHandler)
    print(f"SZL Org Health running on port {port} (Schema v{SCHEMA_VERSION})")
    server.serve_forever()


if __name__ == "__main__":
    run()