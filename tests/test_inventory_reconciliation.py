"""Regression tests for owned-vs-total private repository counter reconciliation.

Context: census run 39350755598 reported FAIL on inventory because the expected count was
built from total_private_repos (plan-quota shaped) while the enumeration returns owned
repositories. On szl-holdings those differ by 2 (owned 19, total 17), so a complete
enumeration of 148 was compared against 146.

Run: python -m unittest discover -s tests -v   (the CI command; collected automatically)
"""
import unittest

from census.file_audit import _reconcile_counts


LIVE = {"public_repos": 129, "total_private_repos": 17, "owned_private_repos": 19}


class ReconcileCounts(unittest.TestCase):
    def test_live_estate_matches_owned_counter(self):
        """The regression: 148 observed must match, via owned_private_repos."""
        out = _reconcile_counts(LIVE, 148)
        self.assertTrue(out["matched"])
        self.assertEqual(out["authoritative_counter_used"], "owned_private_repos")
        self.assertEqual(out["authoritative_expected_count"], 148)

    def test_counter_disagreement_is_recorded_not_hidden(self):
        out = _reconcile_counts(LIVE, 148)
        self.assertTrue(out["counters_disagree"])
        self.assertEqual(out["authoritative_expected_counts"],
                         {"owned_private_repos": 148, "total_private_repos": 146})

    def test_quota_counter_cannot_override_available_owned_counter(self):
        for owned, quota in ((2, 1), (1, 2)):
            with self.subTest(owned=owned, quota=quota):
                out = _reconcile_counts(
                    {"public_repos": 3, "owned_private_repos": owned,
                     "total_private_repos": quota},
                    3 + quota,
                )
                self.assertFalse(out["matched"])
                self.assertEqual(out["authoritative_expected_count"], 3 + owned)
                self.assertIsNone(out["authoritative_counter_used"])
                self.assertTrue(out["counters_disagree"])

    def test_owned_match_is_valid_despite_quota_counter_disagreement(self):
        for owned, quota in ((2, 1), (1, 2)):
            with self.subTest(owned=owned, quota=quota):
                out = _reconcile_counts(
                    {"public_repos": 3, "owned_private_repos": owned,
                     "total_private_repos": quota},
                    3 + owned,
                )
                self.assertTrue(out["matched"])
                self.assertEqual(out["authoritative_counter_used"], "owned_private_repos")
                self.assertEqual(out["authoritative_expected_count"], 3 + owned)
                self.assertTrue(out["counters_disagree"])

    def test_genuine_gap_still_fails_closed(self):
        """An observation matching NEITHER counter must not pass."""
        out = _reconcile_counts(LIVE, 147)
        self.assertFalse(out["matched"])
        self.assertIsNone(out["authoritative_counter_used"])

    def test_missing_repo_fails_closed(self):
        self.assertFalse(_reconcile_counts(LIVE, 140)["matched"])

    def test_extra_repo_fails_closed(self):
        self.assertFalse(_reconcile_counts(LIVE, 149)["matched"])

    def test_total_counter_alone_still_works(self):
        out = _reconcile_counts({"public_repos": 129, "total_private_repos": 17}, 146)
        self.assertTrue(out["matched"])
        self.assertEqual(out["authoritative_counter_used"], "total_private_repos")
        self.assertFalse(out["counters_disagree"])

    def test_owned_counter_alone_still_works(self):
        out = _reconcile_counts({"public_repos": 129, "owned_private_repos": 19}, 148)
        self.assertTrue(out["matched"])
        self.assertEqual(out["authoritative_counter_used"], "owned_private_repos")

    def test_agreeing_counters_report_no_disagreement(self):
        out = _reconcile_counts({"public_repos": 10, "total_private_repos": 2,
                                 "owned_private_repos": 2}, 12)
        self.assertTrue(out["matched"])
        self.assertFalse(out["counters_disagree"])

    def test_unavailable_when_no_private_counter(self):
        out = _reconcile_counts({"public_repos": 129}, 148)
        self.assertFalse(out["authoritative_count_available"])
        self.assertIsNone(out["matched"])

    def test_unavailable_when_public_missing(self):
        self.assertFalse(_reconcile_counts({"owned_private_repos": 19}, 19)["authoritative_count_available"])

    def test_non_dict_org_value(self):
        self.assertFalse(_reconcile_counts(None, 148)["authoritative_count_available"])

    def test_bool_is_not_a_count(self):
        """True == 1 in Python; a bool must not be accepted as a counter."""
        out = _reconcile_counts({"public_repos": True, "owned_private_repos": 19}, 20)
        self.assertFalse(out["authoritative_count_available"])

    def test_negative_counter_rejected(self):
        out = _reconcile_counts({"public_repos": 129, "owned_private_repos": -1}, 128)
        self.assertFalse(out["authoritative_count_available"])

    def test_zero_counts_are_valid(self):
        out = _reconcile_counts({"public_repos": 0, "owned_private_repos": 0}, 0)
        self.assertTrue(out["authoritative_count_available"])
        self.assertTrue(out["matched"])


if __name__ == "__main__":
    unittest.main()
