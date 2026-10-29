from __future__ import annotations

import copy
import datetime as dt
import json
import unittest
from pathlib import Path
from unittest import mock

import app
from census.portal_projection import SCHEMA, project_portal_index

ROOT = Path(__file__).resolve().parents[1]
SNAPSHOT = ROOT / "static" / "data.json"
SENTINEL = "private-portal-sentinel-8c42e1"


def fresh_public_report(now: dt.datetime) -> dict:
    report = json.loads(SNAPSHOT.read_text(encoding="utf-8"))
    started = now - dt.timedelta(seconds=2)
    completed = now - dt.timedelta(seconds=1)
    report["generated_at"] = started.isoformat().replace("+00:00", "Z")
    report["collection"] = {
        "schema": "szl.census-collection/v1",
        "id": "a" * 32,
        "started_at": report["generated_at"],
        "completed_at": completed.isoformat().replace("+00:00", "Z"),
    }
    return report


class PortalProjectionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.now = dt.datetime(2026, 10, 29, 12, 0, tzinfo=dt.UTC)
        self.report = fresh_public_report(self.now)

    def test_private_extensions_and_rows_never_enter_index(self) -> None:
        clean = project_portal_index(self.report, as_of=self.now)
        tainted = copy.deepcopy(self.report)
        tainted["sources"]["github"]["data"]["repos"][SENTINEL] = {
            "visibility": "private",
            "private": True,
            "message": SENTINEL,
        }
        tainted["sources"]["huggingface"]["data"]["assets"]["models"]["items"].append(
            {"id": "SZLHOLDINGS/" + SENTINEL, "private": True, "message": SENTINEL}
        )
        tainted["sources"]["sites"]["data"]["a-11-oy.com"]["message"] = SENTINEL
        tainted["sources"]["sites"]["error"] = SENTINEL
        index = project_portal_index(tainted, as_of=self.now)
        self.assertNotIn(SENTINEL, json.dumps(index))
        self.assertEqual(index["layers"], clean["layers"])
        internal = copy.deepcopy(self.report)
        internal["exposure"] = "internal"
        with self.assertRaises(ValueError):
            project_portal_index(internal, as_of=self.now)

    def test_stale_or_absent_collection_cannot_claim_current_observation(self) -> None:
        stale = project_portal_index(
            self.report, as_of=self.now + dt.timedelta(days=2)
        )
        self.assertFalse(stale["freshness"]["within_24h"])
        self.assertGreater(stale["freshness"]["age_seconds"], 86400)
        for layer in stale["layers"].values():
            self.assertEqual(layer["evidence_class"], "UNKNOWN")
        self.assertIsNone(stale["layers"]["product"]["http_status"])
        self.assertIsNone(stale["layers"]["github"]["public_repositories"])
        self.assertTrue(
            all(value is None for value in stale["layers"]["huggingface"]["public_asset_counts"].values())
        )

        missing = copy.deepcopy(self.report)
        missing["collection"] = None
        absent = project_portal_index(missing, as_of=self.now)
        self.assertIsNone(absent["freshness"]["age_seconds"])
        self.assertFalse(absent["freshness"]["within_24h"])
        self.assertEqual(absent["layers"]["proof"]["evidence_class"], "UNKNOWN")

    def test_http_200_is_transport_only(self) -> None:
        index = project_portal_index(self.report, as_of=self.now)
        self.assertEqual(index["schema"], SCHEMA)
        self.assertTrue(index["freshness"]["within_24h"])
        self.assertEqual(index["layers"]["product"]["http_status"], 200)
        self.assertEqual(index["layers"]["product"]["evidence_class"], "MEASURED")
        self.assertEqual(index["layers"]["product"]["scope"], "http-transport")
        self.assertTrue(all(value == "UNKNOWN" for value in index["claim_boundaries"].values()))
        self.assertNotIn("source_snapshot_sha256", index)

    def test_route_reuses_one_public_report_without_new_provider_call(self) -> None:
        current = dt.datetime.now(dt.UTC).replace(microsecond=0)
        handler = object.__new__(app.Handler)
        handler.path = "/api/portal?test=1"
        with (
            mock.patch.object(app, "build_report", return_value=fresh_public_report(current)) as report,
            mock.patch.object(app.Handler, "_send") as send,
        ):
            handler.do_GET()
        report.assert_called_once_with()
        self.assertEqual(send.call_args.args[0], 200)
        body = json.loads(send.call_args.args[1])
        self.assertEqual(body["schema"], SCHEMA)
        self.assertEqual(body["claim_boundaries"]["release_authority"], "UNKNOWN")


if __name__ == "__main__":
    unittest.main()
