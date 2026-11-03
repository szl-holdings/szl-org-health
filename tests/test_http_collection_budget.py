"""HTTP misses cannot multiply provider work or queue unlimited handlers."""
from __future__ import annotations

import concurrent.futures
import datetime as dt
import http.client
import json
import socket
import threading
import unittest
from unittest.mock import patch

import app
from tests.test_portal_projection import fresh_public_report


class ObservedResponses(app.PublicResponses):
    def __init__(self):
        super().__init__()
        self.completed = threading.Event()

    def _refresh(self):
        try:
            super()._refresh()
        finally:
            self.completed.set()


class ResponseBudgetTests(unittest.TestCase):
    def setUp(self):
        self.cache = ObservedResponses()
        self.report = fresh_public_report(dt.datetime.now(dt.UTC).replace(microsecond=0))

    def finish(self):
        self.assertTrue(self.cache.completed.wait(5), "background refresh did not finish")

    def test_parallel_misses_share_one_refresh_and_never_wait_for_it(self):
        entered, release = threading.Event(), threading.Event()

        def collect(**kwargs):
            entered.set()
            if not release.wait(5):
                raise RuntimeError("test refresh was not released")
            return self.report

        def request(index):
            with self.assertRaises(app.ReportUnavailable):
                self.cache.get(("/api/health", "/api/portal")[index % 2])

        with patch.object(app, "build_report", side_effect=collect) as build:
            try:
                with concurrent.futures.ThreadPoolExecutor(max_workers=16) as callers:
                    futures = [callers.submit(request, i) for i in range(64)]
                    for future in futures:
                        future.result(timeout=2)
                self.assertTrue(entered.wait(2))
                self.assertEqual(build.call_count, 1)
            finally:
                release.set()
                self.finish()
            health = json.loads(self.cache.get("/api/health"))
            portal = json.loads(self.cache.get("/api/portal"))
            self.assertEqual(health, self.report)
            self.assertEqual(health["generated_at"], portal["generated_at"])
            self.assertTrue(all(v == "UNKNOWN" for v in portal["claim_boundaries"].values()))
            build.assert_called_once_with(exposure="public", use_cache=False)

    def test_cache_ttl_begins_at_completion_and_expiry_does_not_serve_old_data(self):
        clock = [100.0]

        def collect(**kwargs):
            clock[0] = 200.0  # The collection itself consumed a full interval.
            return self.report

        with patch.object(app.time, "monotonic", side_effect=lambda: clock[0]):
            with patch.object(app, "build_report", side_effect=collect) as build:
                with self.assertRaises(app.ReportUnavailable):
                    self.cache.get("/api/health")
                self.finish()
                clock[0] = 259.0
                self.assertEqual(json.loads(self.cache.get("/api/health")), self.report)
                build.assert_called_once()
            clock[0] = 260.0
            self.cache.completed.clear()
            with patch.object(app, "build_report", side_effect=RuntimeError("private-error")) as build:
                with self.assertRaises(app.ReportUnavailable):
                    self.cache.get("/api/health")
                self.finish()
                for _ in range(20):
                    with self.assertRaises(app.ReportUnavailable):
                        self.cache.get("/api/portal")
                build.assert_called_once()

    def test_failed_refresh_backs_off_then_recovers(self):
        clock = [100.0]
        with patch.object(app.time, "monotonic", side_effect=lambda: clock[0]):
            with patch.object(app, "build_report", side_effect=RuntimeError("private-error")) as build:
                with self.assertRaises(app.ReportUnavailable):
                    self.cache.get("/api/health")
                self.finish()
                clock[0] = 159.0
                with self.assertRaises(app.ReportUnavailable):
                    self.cache.get("/api/health")
                build.assert_called_once()
            clock[0] = 160.0
            self.cache.completed.clear()
            with patch.object(app, "build_report", return_value=self.report) as build:
                with self.assertRaises(app.ReportUnavailable):
                    self.cache.get("/api/health")
                self.finish()
                self.assertEqual(json.loads(self.cache.get("/api/health")), self.report)
                build.assert_called_once()

    def test_invalid_public_result_never_becomes_cached_success(self):
        for value in (None, {}, {"exposure": "internal"}):
            self.cache = ObservedResponses()
            with patch.object(app, "build_report", return_value=value) as build:
                with self.assertRaises(app.ReportUnavailable):
                    self.cache.get("/api/health")
                self.finish()
                with self.assertRaises(app.ReportUnavailable):
                    self.cache.get("/api/health")
                build.assert_called_once()

    def test_thread_start_failure_backs_off_without_leaking_exception(self):
        with patch.object(app.threading.Thread, "start", side_effect=RuntimeError("private-error")) as start:
            for _ in range(10):
                with self.assertRaises(app.ReportUnavailable) as error:
                    self.cache.get("/api/health")
                self.assertNotIn("private-error", str(error.exception))
            start.assert_called_once()


class HTTPBudgetTests(unittest.TestCase):
    def start_server(self, handler=app.Handler, server_type=app.BoundedHTTPServer):
        server = server_type(("127.0.0.1", 0), handler)
        thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True)
        thread.start()
        self.addCleanup(thread.join, 5)
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        return server

    def request(self, server, path):
        conn = http.client.HTTPConnection(*server.server_address, timeout=2)
        try:
            conn.request("GET", path)
            response = conn.getresponse()
            return response.status, dict(response.getheaders()), response.read()
        finally:
            conn.close()

    def test_real_http_misses_are_prompt_and_liveness_survives_blocked_provider(self):
        cache = ObservedResponses()
        release = threading.Event()
        report = fresh_public_report(dt.datetime.now(dt.UTC).replace(microsecond=0))

        def collect(**kwargs):
            if not release.wait(5):
                raise RuntimeError("test refresh was not released")
            return report

        server = self.start_server()
        with patch.object(app, "PUBLIC_RESPONSES", cache), patch.object(app, "build_report", side_effect=collect) as build:
            try:
                for path in ("/api/health", "/api/portal?fresh=1") * 8:
                    status, headers, body = self.request(server, path)
                    self.assertEqual(status, 503)
                    self.assertEqual(headers["Retry-After"], "60")
                    self.assertEqual(headers["Cache-Control"], "no-store")
                    self.assertEqual(json.loads(body), {"error": "UNAVAILABLE"})
                status, _, body = self.request(server, "/healthz")
                self.assertEqual(status, 200)
                self.assertEqual(json.loads(body)["status"], "ok")
            finally:
                release.set()
                self.assertTrue(cache.completed.wait(5))
            for path in ("/api/health", "/api/portal"):
                self.assertEqual(self.request(server, path)[0], 200)
            build.assert_called_once()

    def test_handler_capacity_is_bounded_and_released(self):
        entered = threading.Barrier(3)
        release = threading.Event()
        count = []

        class TwoSlots(app.BoundedHTTPServer):
            max_handlers = 2

        class HeldHandler(app.Handler):
            def do_GET(self):
                if self.path == "/hold":
                    count.append(1)
                    entered.wait(timeout=5)
                    release.wait(5)
                self._send(200, "{}")

        server = self.start_server(HeldHandler, TwoSlots)
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as clients:
            held = [clients.submit(self.request, server, "/hold") for _ in range(2)]
            try:
                entered.wait(timeout=5)
                with self.assertRaises((ConnectionError, http.client.RemoteDisconnected)):
                    self.request(server, "/overflow")
                self.assertEqual(len(count), 2)
            finally:
                release.set()
                for future in held:
                    self.assertEqual(future.result(timeout=5)[0], 200)
        # Prove that handler completion releases both admission slots.
        self.assertTrue(server._slots.acquire(timeout=2))
        self.assertTrue(server._slots.acquire(timeout=2))
        server._slots.release()
        server._slots.release()
        self.assertEqual(self.request(server, "/healthz")[0], 200)

    def test_accepted_socket_has_timeout(self):
        with app.BoundedHTTPServer(("127.0.0.1", 0), app.Handler) as server:
            with socket.create_connection(server.server_address, timeout=2):
                accepted, _ = server.get_request()
                try:
                    self.assertEqual(accepted.gettimeout(), 5.0)
                finally:
                    accepted.close()


if __name__ == "__main__":
    unittest.main()
