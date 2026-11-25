"""Offline adversarial tests for bounded public Space runtime triage."""
import json
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest.mock import patch
from tools.hf_space_runtime_triage import (
    BASE, LIMIT, CensusUnavailable, _unique_pairs, audit, fetch_json,
)


def row(name="a11oy", sha="a" * 40, private=False):
    return {"id": "SZLHOLDINGS/" + name, "sha": sha, "private": private}


def fake(rows, stages=None):
    stages = stages or {}
    def fetch(url):
        if "?author=" in url:
            return rows
        name = url.split("/api/spaces/", 1)[1].split("?")[0]
        stage, sha = stages.get(name, ("RUNNING", "a" * 40))
        return {"runtime": {"stage": stage, "sha": sha}}
    return fetch


class TriageTests(unittest.TestCase):
    def test_matched_never_production(self):
        r = audit(fake([row()]))
        self.assertEqual(r["counts"], {"RUNNING_REVISION_MATCHED": 1})
        self.assertEqual(r["checked"], r["denominator"])
        self.assertFalse(r["production_authorized"])
        self.assertEqual(r["application_readiness"], "UNAVAILABLE")
        self.assertEqual(r["source_binding"], "UNVERIFIED")

    def test_paused_and_sleeping_preserved(self):
        rows = [row("a11oy"), row("paused"), row("sleep")]
        f = fake(rows, {"SZLHOLDINGS/paused": ("PAUSED", None),
                        "SZLHOLDINGS/sleep": ("SLEEPING", None)})
        r = audit(f)
        self.assertEqual(r["counts"]["PAUSED"], 1)
        self.assertEqual(r["counts"]["SLEEPING"], 1)
        self.assertEqual(len(r["nonmatching_public_spaces"]), 2)

    def test_revision_drift(self):
        r = audit(fake([row()], {"SZLHOLDINGS/a11oy": ("RUNNING", "b" * 40)}))
        self.assertEqual(r["counts"], {"RUNNING_REVISION_DRIFT": 1})

    def test_missing_sha_is_unknown_not_match(self):
        r = audit(fake([row(sha=None)]))
        self.assertEqual(r["counts"], {"RUNNING_REVISION_UNKNOWN": 1})

    def test_private_visibility_denied(self):
        with self.assertRaises(CensusUnavailable):
            audit(fake([row(private=True)]))
        with self.assertRaises(CensusUnavailable):
            audit(fake([{"id": "SZLHOLDINGS/a11oy", "sha": "a" * 40}]))

    def test_duplicate_identity_denied(self):
        with self.assertRaises(CensusUnavailable):
            audit(fake([row(), row()]))

    def test_incomplete_page_denied(self):
        with self.assertRaises(CensusUnavailable):
            audit(fake([row(str(i)) for i in range(LIMIT)]))

    def test_malformed_and_cross_namespace_denied(self):
        for name in ("../admin", "a?x=1", "space/id"):
            with self.subTest(name=name), self.assertRaises(CensusUnavailable):
                audit(fake([row(name)]))
        with self.assertRaises(CensusUnavailable):
            audit(fake([{"id": "OTHER/a11oy", "private": False}]))

    def test_unavailable_detail_not_running(self):
        def broken(url):
            if "?author=" in url:
                return [row()]
            raise OSError("do not log private provider details")
        r = audit(broken)
        self.assertEqual(r["counts"], {"UNAVAILABLE": 1})
        self.assertNotIn("private provider details", json.dumps(r))

    def test_unknown_stage_denied(self):
        r = audit(fake([row()], {"SZLHOLDINGS/a11oy": ("MAGIC_READY", "a" * 40)}))
        self.assertEqual(r["counts"], {"UNAVAILABLE": 1})

    def test_duplicate_json_keys_denied(self):
        with self.assertRaises(CensusUnavailable):
            json.loads('{"runtime":{"stage":"RUNNING","stage":"PAUSED"}}',
                       object_pairs_hook=_unique_pairs)

    def test_redirects_denied_without_contacting_destination(self):
        # Fully offline: the origin and redirect target are loopback only.
        # No Hugging Face Space, production endpoint, or secret is accessed.
        target_hits = []
        redirect_status = [302]

        class Target(BaseHTTPRequestHandler):
            def do_GET(self):
                target_hits.append(self.path)
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b'{"untrusted":true}')

            def log_message(self, *args):
                pass

        target = ThreadingHTTPServer(("127.0.0.1", 0), Target)

        class Origin(BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(redirect_status[0])
                self.send_header(
                    "Location",
                    f"http://127.0.0.1:{target.server_address[1]}/app-runtime",
                )
                self.end_headers()

            def log_message(self, *args):
                pass

        origin = ThreadingHTTPServer(("127.0.0.1", 0), Origin)
        for server in (target, origin):
            threading.Thread(target=server.serve_forever, daemon=True).start()
        try:
            base = f"http://127.0.0.1:{origin.server_address[1]}"
            with patch("tools.hf_space_runtime_triage.BASE", base):
                url = f"{base}/api/spaces?author=SZLHOLDINGS&limit={LIMIT}&full=true"
                for status in (301, 302, 303, 307, 308):
                    with self.subTest(status=status):
                        redirect_status[0] = status
                        with self.assertRaisesRegex(
                            CensusUnavailable, "REDIRECT_NOT_ALLOWED"
                        ):
                            fetch_json(url)
                        self.assertEqual(target_hits, [])
        finally:
            for server in (origin, target):
                server.shutdown()
                server.server_close()

    def test_url_allowlist(self):
        for url in ("https://example.com/", BASE + "/api/whoami-v2",
                    BASE + "/api/spaces/SZLHOLDINGS/a11oy?token=1"):
            with self.assertRaises(CensusUnavailable):
                fetch_json(url)


if __name__ == "__main__":
    unittest.main()
