import unittest

from status_classes.health import (EVIDENCE_INTEGRITY, FRESHNESS, Observation,
                                   ObservationError, PROVIDER_FAILURE, 
                                   classify, ErrorBudget, UNKNOWN)

NOW = 10_000.0


def obs(kind, label, ok, ts, window=100.0):
    return Observation(kind=kind, label=label, ok=ok, observed_ts=ts, window_s=window)


class ObservationTests(unittest.TestCase):
    def test_malformed_kind_rejected(self):
        with self.assertRaises(ObservationError):
            obs("NOT_A_CLASS", "x", True, NOW)

    def test_malformed_window_rejected(self):
        with self.assertRaises(ObservationError):
            obs(PROVIDER_FAILURE, "x", True, NOW, window=0.0)

    def test_malformed_label_rejected(self):
        with self.assertRaises(ObservationError):
            obs(FRESHNESS, "", True, NOW)


class ClassifyTests(unittest.TestCase):
    def test_sections_kept_separate(self):
        r = classify([obs(PROVIDER_FAILURE, "openai", False, NOW),
                      obs(EVIDENCE_INTEGRITY, "receipt-x", False, NOW),
                      obs(FRESHNESS, "census", True, NOW)], now_ts=NOW)
        d = r.as_dict()
        self.assertEqual(set(d.keys()),
                         {"provider_failure", "evidence_integrity", "freshness", "no_merged_status"})
        self.assertTrue(d["no_merged_status"])
        self.assertNotIn("overall", d)  # no single merged red/green key
        # same ok=False evidence kept in its own section
        self.assertEqual(d["evidence_integrity"]["cells"][0]["label"], "receipt-x")

    def test_stale_freshness_is_unknown_never_green(self):
        r = classify([obs(FRESHNESS, "census", True, NOW - 10_000.0)], now_ts=NOW)
        cell = r.as_dict()["freshness"]["cells"][0]
        self.assertEqual(cell["cell_result"], UNKNOWN)
        self.assertFalse(cell["fresh"])

    def test_stale_observations_excluded_from_burn(self):
        # stale failing obs excluded -> in-window burn computed only on fresh ones
        r = classify([obs(PROVIDER_FAILURE, "openai", False, NOW - 10_000.0),
                      obs(PROVIDER_FAILURE, "anthropic", True, NOW)], now_ts=NOW)
        self.assertEqual(r.as_dict()["provider_failure"]["burn"], 0.0)

    def test_absent_class_empty_with_unknown_burn(self):
        r = classify([obs(PROVIDER_FAILURE, "openai", False, NOW)], now_ts=NOW)
        sec = r.as_dict()["evidence_integrity"]
        self.assertEqual(sec["cells"], [])
        self.assertIsNone(sec["burn"])  # UNKNOWN burn, not 0.0

    def test_classify_rejects_non_observation(self):
        with self.assertRaises(ObservationError):
            classify([{"kind": FRESHNESS}], now_ts=NOW)


class BudgetTests(unittest.TestCase):
    def test_burn_fraction_half(self):
        budget = ErrorBudget()
        b = budget.burn(PROVIDER_FAILURE,
                        [obs(PROVIDER_FAILURE, "a", True, NOW),
                         obs(PROVIDER_FAILURE, "b", False, NOW)], now_ts=NOW)
        self.assertEqual(b, 0.5)

    def test_burn_absent_is_none(self):
        self.assertIsNone(ErrorBudget().burn(FRESHNESS, [], now_ts=NOW))

    def test_burn_unknown_class_raises(self):
        with self.assertRaises(ObservationError):
            ErrorBudget().burn("bogus", [], now_ts=NOW)

    def test_burn_never_crosses_classes(self):
        b = ErrorBudget().burn(EVIDENCE_INTEGRITY,
                               [obs(PROVIDER_FAILURE, "a", False, NOW)], now_ts=NOW)
        self.assertIsNone(b)  # other classes' failures do not leak in


if __name__ == "__main__":
    unittest.main()
