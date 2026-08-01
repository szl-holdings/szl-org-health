#!/usr/bin/env python3
"""SZL Org Health — live schema-v2 estate census and HTTP service."""
from __future__ import annotations

import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from census import SCHEMA_VERSION, build_report
from census.common import resolve_txt as _resolve_txt
from census.sites import DOMAINS


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
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self):  # noqa: N802 - BaseHTTPRequestHandler API
        path = self.path.split("?", 1)[0]
        if path == "/api/health":
            self._send(200, json.dumps(build_report(), separators=(",", ":")))
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
    server = ThreadingHTTPServer(("0.0.0.0", port), Handler)
    print(f"szl-org-health serving on 0.0.0.0:{port}", flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
