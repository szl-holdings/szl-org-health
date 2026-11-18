#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Source-bound, fail-closed design map over synthetic PUBLIC census fixtures.

Never connects to GitHub, Hugging Face, Cloudflare, PyPI or Neon.
"""
from __future__ import annotations

import copy
import datetime as dt
import http.client
import json
import threading
import unittest.mock

import app
from census.portal_projection import project_portal_index
from census.system_design import (
    REFERENCE, SCHEMA, project_system_design, render_html,
)
from tests.test_portal_projection import fresh_public_report

SECRET = "private-credential-DO-NOT-DISCLOSE-9137"


class SystemDesignProjectionTests(unittest.TestCase):
    def setUp(self):
        self.now = dt.datetime.now(dt.UTC).replace(microsecond=0)
        self.public = fresh_public_report(self.now)
        self.portal = project_portal_index(self.public, as_of=self.now)

    def test_exact_external_reference_is_readme_catalog_not_runnable_package(self):
        self.assertEqual(REFERENCE["revision"], "b92daa9595f23974e64e55d8ad0a942d75a64d56")
        self.assertEqual(REFERENCE["readme_sha256"], "88b2fb2c7274c23658547b287a6e86ff6a4a095136cf850d877d183c717fccc5")
        self.assertEqual(REFERENCE["license"], "MIT")
        self.assertEqual(REFERENCE["tracked_files"], 2)
        self.assertEqual(REFERENCE["kind"], "EDUCATIONAL_LINK_CATALOG_NOT_SOFTWARE")

    def test_source_only_map_makes_no_quality_or_authorization_claims(self):
        data = project_system_design(self.portal)
        self.assertEqual(data["schema"], SCHEMA)
        self.assertEqual(data["mode"], "READ_ONLY_DESIGN_REVIEW")
        self.assertFalse(data["production_ready"])
        self.assertFalse(data["model_qualified"])
        self.assertFalse(data["private_estate_included"])
        self.assertFalse(data["payment_settlement_verified"])
        self.assertFalse(data["pypi_oidc_verified"])
        self.assertFalse(data["signature_created"])
        self.assertEqual(data["provider_writes"], 0)
        self.assertEqual(len(data["controls"]), 11)
        self.assertEqual(len(set(c["id"] for c in data["controls"])), 11)
        for control in data["controls"]:
            self.assertEqual(control["qualification"], "NOT_EVALUATED")
            self.assertFalse(control["action_authorized"])
            self.assertTrue(control["candidate_owner"].startswith("szl-holdings/"))
            self.assertTrue(control["candidate_owner_url"].startswith("https://github.com/szl-holdings/"))
            self.assertNotIn("PASS", control["qualification"])
        self.assertEqual(sum(c["pattern_source"] == "SZL_EXTENSION" for c in data["controls"]), 1)
        self.assertTrue(all(row["state"] == "NOT_VERIFIED" for row in data["release_chain"]))

    def test_public_measured_status_never_becomes_production_qualified(self):
        data = project_system_design(self.portal)
        values = {x["id"]: x for x in data["platforms"]}
        self.assertEqual(set(values), {"github", "huggingface", "product", "proof", "cloudflare", "pypi"})
        self.assertEqual(values["cloudflare"]["observation"], "UNKNOWN")
        self.assertEqual(values["pypi"]["observation"], "UNKNOWN")
        for row in values.values():
            self.assertFalse(row["production_qualified"])
        for id_ in ("product", "proof"):
            if values[id_]["observation"] != "UNKNOWN":
                self.assertEqual(values[id_]["observation"], "HTTP_TRANSPORT_OBSERVED")
                self.assertIsInstance(values[id_]["observed_count_or_http"], int)
                self.assertNotEqual(values[id_]["scope"], "action-authority")

    def test_private_and_attacker_controlled_fields_cannot_escape(self):
        poisoned = copy.deepcopy(self.portal)
        poisoned["layers"]["github"]["raw_token"] = SECRET
        poisoned["layers"]["huggingface"]["private_assets"] = [{"id": SECRET}]
        poisoned["layers"]["product"]["arbitrary_info"] = SECRET
        poisoned["freshness"]["raw_provider_text"] = SECRET
        poisoned["claim_boundaries"]["release_authority"] = SECRET
        poisoned["layers"]["cloudflare"] = {"scope": "http-transport",
                                           "evidence_class": "MEASURED",
                                           "http_status": 200, "secret": SECRET}
        report = project_system_design(poisoned)
        self.assertNotIn(SECRET, json.dumps(report))
        self.assertEqual(next(x for x in report["platforms"] if x["id"] == "cloudflare")["observation"], "UNKNOWN")

    def test_staleness_demotes_every_measured_layer(self):
        stale = project_portal_index(self.public, as_of=self.now + dt.timedelta(days=2))
        data = project_system_design(stale)
        self.assertIsNone(data["estate_observed_at"])
        self.assertEqual(data["freshness"], "UNAVAILABLE_OR_STALE")
        self.assertTrue(all(row["observation"] == "UNKNOWN" for row in data["platforms"]))
        self.assertFalse(data["production_ready"])

    def test_odd_timestamps_and_coerced_http_codes_never_get_observation(self):
        bad = copy.deepcopy(self.portal)
        bad["layers"]["product"] = {"evidence_class": "MEASURED", "scope": "http-transport", "http_status": True}
        bad["layers"]["github"] = {"evidence_class": "MEASURED", "scope": "public-repository-subset", "public_repositories": "174"}
        bad["layers"]["huggingface"] = {"evidence_class": "MEASURED", "scope": "public-asset-subsets",
                                        "public_asset_counts": {"models": True}}
        data = project_system_design(bad)
        states = {row["id"]: row["observation"] for row in data["platforms"]}
        self.assertEqual(states["product"], states["github"])
        self.assertEqual(states["product"], states["huggingface"])
        self.assertEqual(states["product"], "UNKNOWN")
        bad["generated_at"] = "not-a-real-time"
        self.assertTrue(all(row["observation"] == "UNKNOWN" for row in project_system_design(bad)["platforms"]))

    def test_closed_portal_schema_is_required(self):
        for invalid in (None, {}, {"schema": "szl.fake-report/v1"}, self.public):
            with self.assertRaises(ValueError):
                project_system_design(invalid)

    def test_html_is_python_rendered_and_escaped(self):
        snapshot = project_system_design(self.portal)
        html = render_html(snapshot).decode("utf-8")
        self.assertIn("System design, grounded in evidence", html)
        self.assertIn("NOT_EVALUATED", html)
        self.assertIn("PyPI", html)
        self.assertIn("Cloudflare monetization", html)
        self.assertIn("RELEASE", html.upper())
        self.assertNotIn("<script", html)
        self.assertNotIn("<form", html)
        poison = copy.deepcopy(snapshot)
        poison["controls"][0]["title"] = "<svg onload=alert(1)>"
        poison["platforms"][0]["title"] = '"><script>alert(1)</script>'
        rendered = render_html(poison).decode("utf-8")
        self.assertIn("&lt;svg onload=alert(1)&gt;", rendered)
        self.assertNotIn("<script", rendered)
        self.assertNotIn("<svg", rendered)

    def test_renderer_refuses_unreviewed_external_links_and_source_promotion(self):
        correct = project_system_design(self.portal)
        invalid = copy.deepcopy(correct)
        invalid["controls"][0]["candidate_owner_url"] = "javascript:alert(1)"
        with self.assertRaisesRegex(ValueError, "unapproved owner URL"):
            render_html(invalid)
        invalid = copy.deepcopy(correct)
        invalid["platforms"][0]["url"] = "https://evil.example.invalid"
        with self.assertRaisesRegex(ValueError, "unapproved platform URL"):
            render_html(invalid)
        invalid = copy.deepcopy(correct)
        invalid["production_ready"] = True
        with self.assertRaisesRegex(ValueError, "invalid design-map schema"):
            render_html(invalid)


class SystemDesignCacheTests(unittest.TestCase):
    def setUp(self):
        self.now = dt.datetime.now(dt.UTC).replace(microsecond=0)
        self.public = fresh_public_report(self.now)

    def test_one_existing_public_refresh_supplies_json_and_html(self):
        cache = app.PublicResponses()
        with unittest.mock.patch.object(app, "build_report", return_value=self.public) as build:
            cache._refresh()
        build.assert_called_once_with(exposure="public", use_cache=False)
        health = json.loads(cache.get("/api/health"))
        portal = json.loads(cache.get("/api/portal"))
        architecture = json.loads(cache.get("/api/system-design"))
        page = cache.get("/system-design").decode()
        self.assertEqual(health, self.public)
        self.assertEqual(architecture["generated_from"], portal["schema"])
        self.assertEqual(architecture["estate_observed_at"], portal["generated_at"])
        self.assertIn("no execution permission", page)
        self.assertEqual(architecture["provider_writes"], 0)

    def test_optional_design_failure_does_not_poison_existing_owners(self):
        cache = app.PublicResponses()
        with (
            unittest.mock.patch.object(app, "build_report", return_value=self.public) as build,
            unittest.mock.patch.object(app, "project_system_design", side_effect=RuntimeError(SECRET)),
        ):
            cache._refresh()
        build.assert_called_once()
        self.assertEqual(json.loads(cache.get("/api/health")), self.public)
        self.assertIn("layers", json.loads(cache.get("/api/portal")))
        with self.assertRaises(app.ReportUnavailable):
            cache.get("/api/system-design")
        with self.assertRaises(app.ReportUnavailable):
            cache.get("/system-design")

    def test_missing_or_expired_data_never_reuses_positive_html(self):
        cache = app.PublicResponses()
        with unittest.mock.patch.object(app, "build_report", return_value=self.public):
            cache._refresh()
        self.assertTrue(cache.get("/system-design"))
        cache._expires_at = 0
        cache._retry_at = float("inf")
        for path in ("/api/system-design", "/system-design"):
            with self.assertRaises(app.ReportUnavailable):
                cache.get(path)


class SystemDesignHTTPTests(unittest.TestCase):
    def test_real_http_serves_same_cached_result_with_csp_and_denied_mutations(self):
        cache = app.PublicResponses()
        now = dt.datetime.now(dt.UTC).replace(microsecond=0)
        with unittest.mock.patch.object(app, "build_report", return_value=fresh_public_report(now)):
            cache._refresh()
        server = app.BoundedHTTPServer(("127.0.0.1", 0), app.Handler)
        thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True)
        thread.start()
        try:
            with unittest.mock.patch.object(app, "PUBLIC_RESPONSES", cache):
                def request(method, path):
                    connection = http.client.HTTPConnection(*server.server_address, timeout=2)
                    try:
                        connection.request(method, path)
                        response = connection.getresponse()
                        return response.status, dict(response.getheaders()), response.read()
                    finally:
                        connection.close()
                status, headers, body = request("GET", "/api/system-design")
                self.assertEqual(status, 200)
                self.assertEqual(headers["Cache-Control"], "no-store")
                self.assertEqual(json.loads(body)["schema"], SCHEMA)
                status, headers, body = request("GET", "/system-design")
                self.assertEqual(status, 200)
                self.assertIn("script-src 'none'", headers["Content-Security-Policy"])
                self.assertIn("frame-ancestors 'none'", headers["Content-Security-Policy"])
                self.assertIn(b"System design, grounded in evidence", body)
                self.assertNotIn(b"<script", body)
                for path in ("/api/system-design?model=private", "/system-design?approve=1"):
                    status, _, body = request("GET", path)
                    self.assertEqual(status, 400)
                    self.assertEqual(json.loads(body)["error"], "UNSUPPORTED_QUERY")
                self.assertEqual(request("POST", "/api/system-design")[0], 501)
                self.assertEqual(request("GET", "/api/system-design/approve")[0], 404)
                self.assertEqual(request("GET", "/healthz")[0], 200)
        finally:
            server.shutdown()
            server.server_close()
            thread.join(3)


if __name__ == "__main__":
    unittest.main()
