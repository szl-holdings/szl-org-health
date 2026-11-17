"""Contract: the scheduled estate census receives only an admitted HF reader."""
from __future__ import annotations

import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "scheduled-estate-census.yml"


class CensusCredentialBoundaryTests(unittest.TestCase):
    def test_dedicated_read_secret_is_only_hf_census_credential(self):
        source = WORKFLOW.read_text(encoding="utf-8")
        token_bindings = re.findall(r"(?m)^\\s{10}HF_TOKEN:\\s*(.+)$", source)
        present_bindings = re.findall(r"(?m)^\\s{10}HAS_HF_TOKEN:\\s*(.+)$", source)
        self.assertEqual(token_bindings, ["${{ secrets.HF_CENSUS_READ_TOKEN }}"])
        self.assertEqual(present_bindings, ["${{ secrets.HF_CENSUS_READ_TOKEN != '' }}"])
        self.assertEqual(source.count("HF_CENSUS_READ_TOKEN"), 2)
        for alias in ("HF_ORG_TOKEN", "HF_ORG_TOKEN1", "HUGGINGFACE_TOKEN", "HUGGING_FACE_HUB_TOKEN"):
            self.assertNotIn(f"secrets.{alias}", source)

    def test_existing_fail_closed_census_controls_remain(self):
        source = WORKFLOW.read_text(encoding="utf-8")
        for required in (
            "name: Scheduled estate census",
            "python -I -B census/receipt.py --snapshot census-internal.json",
            "--minimum-repositories 123",
            "name: census / fail-closed evidence",
            "ref: ${{ github.sha }}",
            "name: Remove internal census evidence",
        ):
            with self.subTest(required=required):
                self.assertIn(required, source)


if __name__ == "__main__":
    unittest.main()
