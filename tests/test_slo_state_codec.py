"""Lossless history capacity and distinct-slot recovery regressions."""

import base64
import datetime as dt
import lzma
import random
import unittest
import zlib
from pathlib import Path
import tempfile
from unittest.mock import MagicMock, patch

from autonomic import slo_controller as slo


class StateCodecTests(unittest.TestCase):
    def test_legacy_history_migrates_without_changing_any_measurement(self):
        state = slo.empty_state()
        state["healthy_cycles"] = 2
        state["surface_history"] = {
            "a11oy": {"buckets": [[1788480000, 3, 1, 1, 8100, 1788480600]]}
        }
        legacy = base64.b64encode(zlib.compress(slo.canonical_json(state), 9)).decode("ascii")
        self.assertEqual(slo.decode_state(legacy), state)
        body = slo.issue_state_body(slo.decode_state(legacy), {})
        self.assertIn(slo.STATE_BEGIN + "xz:", body)
        self.assertEqual(slo.extract_state(body), state)

    def test_complete_fourteen_day_history_fits_without_removing_samples(self):
        state = slo.empty_state()
        rng = random.Random(19)
        for surface in ("a11oy", "killinchu", "sentra", "lyte", "finance", "terra", "counsel"):
            state["surface_history"][surface] = {
                "buckets": [
                    [epoch, 3, 1 if index % 73 == 0 else 0, 0, rng.randrange(100, 1000), epoch + 600]
                    for index, epoch in enumerate(range(1788480000, 1788480000 + 14 * 86400, 900))
                ]
            }
        old = base64.b64encode(zlib.compress(slo.canonical_json(state), 9))
        self.assertGreater(len(old), slo.MAX_ISSUE_BODY_BYTES)
        body = slo.issue_state_body(state, {})
        self.assertLessEqual(len(body.encode()), slo.MAX_ISSUE_BODY_BYTES)
        self.assertEqual(slo.extract_state(body), state)

    def test_both_codecs_reject_truncation_trailing_data_and_output_overflow(self):
        state = slo.empty_state()
        raw = slo.canonical_json(state)
        for prefix, compressed in (("", zlib.compress(raw)), ("xz:", lzma.compress(raw))):
            with self.subTest(codec=prefix):
                encoded = prefix + base64.b64encode(compressed).decode("ascii")
                with patch.object(slo, "MAX_STATE_BYTES", len(raw)):
                    self.assertEqual(slo.decode_state(encoded), state)
                with patch.object(slo, "MAX_STATE_BYTES", len(raw) - 1):
                    with self.assertRaises(slo.ContractError):
                        slo.decode_state(encoded)
                for damaged in (compressed[:-1], compressed + b"tail", compressed + compressed):
                    with self.assertRaises(slo.ContractError):
                        slo.decode_state(prefix + base64.b64encode(damaged).decode("ascii"))

    def test_corrupt_existing_state_never_becomes_empty_history(self):
        for prefix, compress in (("", zlib.compress), ("xz:", lzma.compress)):
            for raw in (b"not-json", b"[]", b'{"schema":"wrong"}', b'{"schema":"szl.autonomic-slo-state/v1","surface_history":[]}'):
                with self.subTest(prefix=prefix, raw=raw):
                    with self.assertRaises(slo.ContractError):
                        slo.decode_state(prefix + base64.b64encode(compress(raw)).decode("ascii"))
        encoded = slo.encode_state(slo.empty_state())
        with patch.object(slo, "MAX_STATE_DECODE_MEMORY", 1024):
            with self.assertRaises(slo.ContractError):
                slo.decode_state(encoded)
        with patch.object(slo, "MAX_ISSUE_BODY_BYTES", len(encoded) - 1):
            with self.assertRaises(slo.ContractError):
                slo.decode_state(encoded)

    def test_repeated_slot_cannot_supply_third_healthy_cycle(self):
        state = {"healthy_cycles": 2, "updated_at": "2026-09-26T12:01:00Z"}
        epoch = int(dt.datetime(2026, 9, 26, 12, 0, tzinfo=dt.timezone.utc).timestamp())
        for offset in (-300, 0):
            self.assertEqual(slo.healthy_cycle_count(state, healthy=True, sample_epoch=epoch + offset, cadence_minutes=5), 2)
        self.assertEqual(slo.healthy_cycle_count(state, healthy=True, sample_epoch=epoch + 300, cadence_minutes=5), 3)
        self.assertEqual(slo.healthy_cycle_count(state, healthy=False, sample_epoch=epoch, cadence_minutes=5), 0)
        self.assertEqual(slo.healthy_cycle_count(slo.empty_state(), healthy=True, sample_epoch=epoch, cadence_minutes=5), 1)

    def test_invalid_nested_history_cannot_be_discarded_during_decode(self):
        good = [1788480000, 3, 1, 0, 8100, 1788480600]
        for history in (None, {}, {"buckets": None}, {"buckets": [good, [1, 2]]}, {"buckets": [good, good]}, {"buckets": [[1788480000, 1, 2, 0, 100, 1788480600]]}):
            state = slo.empty_state()
            state["surface_history"] = {"a11oy": history}
            with self.subTest(history=history), self.assertRaises(slo.ContractError):
                slo.decode_state(slo.encode_state(state))

    def test_existing_issue_missing_body_or_surface_fails_before_any_probe_or_write(self):
        from tests.test_autonomic_slo import policy_payload, manifest_payload

        policy = slo.validate_policy(policy_payload())
        manifest = slo.validate_manifest(manifest_payload(), policy=policy)
        partial = slo.empty_state()
        partial["surface_history"] = {"a11oy": {"buckets": []}}
        for body in (None, slo.issue_state_body(partial, {})):
            client = MagicMock()
            client.verified_tip.return_value = "a" * 40
            client.find_open_issue.return_value = {"number": 44, "body": body}
            with (
                self.subTest(body=body is None),
                tempfile.TemporaryDirectory() as temporary,
                patch.object(slo, "GitHubApi", return_value=client),
                patch.object(slo, "load_signed_manifest", return_value=(manifest, "b" * 40, "c" * 64)),
                patch.object(slo, "probe_surface") as probe,
                patch.dict(slo.os.environ, {"GITHUB_TOKEN": "test-value", "GITHUB_SHA": "a" * 40, "GITHUB_REPOSITORY": policy["controller_repository"]}),
            ):
                with self.assertRaises(slo.ContractError):
                    slo.run_live(policy=policy, policy_sha256="d" * 64, output=Path(temporary) / "receipt.json")
                probe.assert_not_called()
                client.update_issue.assert_not_called()
                client.create_issue.assert_not_called()


if __name__ == "__main__":
    unittest.main()
