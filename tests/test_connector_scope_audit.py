"""No private repository name may leak from the diagnostic report."""

import json
import tempfile
import unittest
from datetime import UTC, datetime, timedelta
from pathlib import Path

from tools.connector_scope_audit import InvalidManifest, compare, main

TS = datetime.now(UTC).isoformat()


def manifest(source, repos, timestamp=TS):
    return {"source": source, "observed_at_utc": timestamp, "repositories": repos}


def repo(name, private=False, archived=False):
    return {"name": name, "private": private, "archived": archived}


class CredentialScopeTests(unittest.TestCase):
    def test_identical_views_not_org_completeness(self):
        repos = [repo("public-one"), repo("private-one", True)]
        r = compare(manifest("github_cli", repos), manifest("github_app", repos))
        self.assertEqual(r["state"], "CONSISTENT_VISIBLE_SETS_NOT_ORG_COMPLETENESS")
        self.assertIsNone(r["organization_complete"])
        self.assertFalse(r["enforcement_authorized"])

    def test_private_absence_is_reported_without_name(self):
        secret_name = "client-private-secret-repository"
        cli = manifest("github_cli", [repo("public-one"), repo(secret_name, True)])
        app = manifest("github_app", [repo("public-one")])
        r = compare(cli, app)
        self.assertEqual(r["state"], "SCOPE_OR_INVENTORY_DIVERGENCE")
        self.assertEqual(r["left_only"], {"count": 1, "public": 0, "private": 1})
        self.assertNotIn(secret_name, json.dumps(r))
        self.assertIsNone(r["organization_complete"])

    def test_two_way_drift_not_asymmetric_absence(self):
        left = manifest("github_cli", [repo("a"), repo("b", True)])
        right = manifest("github_app", [repo("a"), repo("c", True)])
        r = compare(left, right)
        self.assertEqual(r["left_only"]["private"], 1)
        self.assertEqual(r["right_only"]["private"], 1)

    def test_public_absence_cannot_hide_as_private_only(self):
        left = manifest("github_cli", [repo("public-one"), repo("p2")])
        right = manifest("github_app", [repo("public-one")])
        self.assertEqual(compare(left, right)["left_only"]["public"], 1)

    def test_stale_comparison_is_unavailable_not_absence(self):
        left = manifest("github_cli", [repo("a")])
        right = manifest("github_app", [repo("a")], (datetime.fromisoformat(TS) - timedelta(hours=1)).isoformat())
        r = compare(left, right)
        self.assertEqual(r["state"], "STALE_SNAPSHOT_UNAVAILABLE")
        self.assertEqual(r["snapshot_skew_seconds"], 3600)

    def test_equally_old_snapshots_must_not_pass(self):
        old = (datetime.fromisoformat(TS) - timedelta(days=2)).isoformat()
        r = compare(
            manifest("github_cli", [repo("same")], old),
            manifest("github_app", [repo("same")], old),
        )
        self.assertEqual(r["snapshot_skew_seconds"], 0)
        self.assertEqual(r["state"], "STALE_SNAPSHOT_UNAVAILABLE")

    def test_future_timestamps_must_not_pass(self):
        future = (datetime.fromisoformat(TS) + timedelta(hours=2)).isoformat()
        r = compare(
            manifest("github_cli", [repo("same")], future),
            manifest("github_app", [repo("same")], future),
        )
        self.assertEqual(r["state"], "STALE_SNAPSHOT_UNAVAILABLE")

    def test_bad_age_limits_fail_closed(self):
        left = manifest("github_cli", [repo("same")])
        right = manifest("github_app", [repo("same")])
        with self.assertRaises(ValueError):
            compare(left, right, max_age_seconds=-1)
        with self.assertRaises(ValueError):
            compare(left, right, max_age_seconds=True)

    def test_metadata_divergence_counts_without_names(self):
        left = manifest("github_cli", [repo("archived", archived=True)])
        right = manifest("github_app", [repo("archived")])
        r = compare(left, right)
        self.assertEqual(r["shared_metadata_mismatch"], 1)
        self.assertEqual(r["state"], "SCOPE_OR_INVENTORY_DIVERGENCE")

    def test_reject_duplicate_names(self):
        left = manifest("github_cli", [repo("a"), repo("a")])
        right = manifest("github_app", [repo("a")])
        with self.assertRaises(InvalidManifest):
            compare(left, right)

    def test_reject_unknown_visibility_or_archive_state(self):
        valid = manifest("github_app", [repo("a")])
        bad = manifest("github_cli", [{"name": "a", "archived": False}])
        with self.assertRaises(InvalidManifest):
            compare(bad, valid)
        bad2 = manifest("github_cli", [{"name": "a", "private": True, "archived": None}])
        with self.assertRaises(InvalidManifest):
            compare(bad2, valid)

    def test_reject_conflicting_private_visibility(self):
        left = manifest("github_cli", [{"name": "a", "private": True, "visibility": "public", "archived": False}])
        with self.assertRaises(InvalidManifest):
            compare(left, manifest("github_app", [repo("a")]))

    def test_require_distinct_sources_and_utc(self):
        with self.assertRaises(InvalidManifest):
            compare(manifest("github_cli", [repo("a")]), manifest("github_cli", [repo("a")]))
        with self.assertRaises(InvalidManifest):
            compare(manifest("github_cli", [repo("a")], "2026-11-20T08:00:00"), manifest("github_app", [repo("a")]))

    def test_cli_report_only_aggregates_on_mismatch(self):
        with tempfile.TemporaryDirectory() as root:
            path = Path(root)
            private_name = "sensitive-private-repo"
            (path / "cli.json").write_text(json.dumps(manifest("github_cli", [repo("a"), repo(private_name, True)])))
            (path / "app.json").write_text(json.dumps(manifest("github_app", [repo("a")])))
            code = main(
                [
                    "--cli",
                    str(path / "cli.json"),
                    "--app",
                    str(path / "app.json"),
                    "--output",
                    str(path / "report.json"),
                ]
            )
            self.assertEqual(code, 1)
            report = (path / "report.json").read_text()
            self.assertNotIn(private_name, report)
            self.assertIn("SCOPE_OR_INVENTORY_DIVERGENCE", report)

    def test_existing_report_is_never_overwritten(self):
        with tempfile.TemporaryDirectory() as root:
            path = Path(root)
            (path / "cli.json").write_text(json.dumps(manifest("github_cli", [repo("a")])))
            (path / "app.json").write_text(json.dumps(manifest("github_app", [repo("a")])))
            out = path / "receipt.json"
            original = b"prior-append-only-evidence\n"
            out.write_bytes(original)
            self.assertEqual(
                main(["--cli", str(path / "cli.json"), "--app", str(path / "app.json"), "--output", str(out)]), 2
            )
            self.assertEqual(out.read_bytes(), original)

    def test_output_cannot_alias_private_input_or_symlink(self):
        with tempfile.TemporaryDirectory() as root:
            path = Path(root)
            cli, app = path / "cli.json", path / "app.json"
            cli.write_text(json.dumps(manifest("github_cli", [repo("private", True)])))
            app.write_text(json.dumps(manifest("github_app", [repo("public")])))
            original = cli.read_bytes()
            self.assertEqual(main(["--cli", str(cli), "--app", str(app), "--output", str(cli)]), 2)
            self.assertEqual(cli.read_bytes(), original)
            link = path / "link.json"
            try:
                link.symlink_to(cli)
            except (OSError, NotImplementedError):
                return  # Some Windows installations prohibit test symlinks
            self.assertEqual(main(["--cli", str(cli), "--app", str(app), "--output", str(link)]), 2)
            self.assertEqual(cli.read_bytes(), original)

    def test_cli_malformed_document_is_fail_closed(self):
        with tempfile.TemporaryDirectory() as root:
            path = Path(root)
            (path / "cli.json").write_text('{"source":"github_cli","source":"github_app"}')
            (path / "app.json").write_text(json.dumps(manifest("github_app", [repo("a")])))
            code = main(
                [
                    "--cli",
                    str(path / "cli.json"),
                    "--app",
                    str(path / "app.json"),
                    "--output",
                    str(path / "report.json"),
                ]
            )
            self.assertEqual(code, 1)
            report = json.loads((path / "report.json").read_text())
            self.assertEqual(report["state"], "UNAVAILABLE")
            self.assertFalse(report["enforcement_authorized"])


if __name__ == "__main__":
    unittest.main()
