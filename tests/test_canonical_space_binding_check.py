"""Source-only negative controls for immutable GitHub -> HF declaration mapping."""

from __future__ import annotations

import hashlib
import json
import unittest

from tools import canonical_space_binding_check as check

SIX = ["a11oy", "killinchu", "terra", "counsel", "finance", "lyte"]
BODIES = {
    "terra": "szl-real-estate",
    "killinchu": "killinchu",
    "counsel": "platform",
    "finance": "puriq-live",
    "lyte": "lyte-services",
}


def fixture():
    manifest = {
        "schema": check.ALIGNMENT_SCHEMA,
        "github_org": "szl-holdings",
        "hub_org": "SZLHOLDINGS",
        "authority": {"governed_fabric": "szl-holdings/a11oy"},
        "hub_alias_policy": {
            "duplicate_authority_spaces_forbidden": True,
            "canonical_public_space_slugs": SIX,
        },
        "public_bodies": [
            {
                "id": "prism-counsel" if slug == "counsel" else slug,
                "hub_surface": "SZLHOLDINGS/" + slug,
                "backend_source": "szl-holdings/" + repo,
            }
            for slug, repo in BODIES.items()
        ],
    }
    lines = [
        "# Historical observation 2026-11-15",
        "| Space | Visibility | SDK | Stage | Source repo | Match |",
        "|---|---|---|---|---|---|",
    ]
    for slug in SIX:
        if slug == "a11oy":
            repo = "a11oy"
        else:
            repo = BODIES[slug]
        lines.append(f"| {slug} | public | docker | RUNNING | {repo} | exact |")
    return manifest, "\n".join(lines).encode("utf-8")


def raw_pin(manifest):
    raw = (json.dumps(manifest, sort_keys=True) + "\n").encode("utf-8")
    return raw, hashlib.sha1(
        b"blob " + str(len(raw)).encode("ascii") + b"\0" + raw
    ).hexdigest()


class SpaceAuthorityTests(unittest.TestCase):
    def test_canonical_six_agree_but_never_claim_runtime(self):
        manifest, historical = fixture()
        raw, pin = raw_pin(manifest)
        result = check.reconcile(raw, pin, historical)
        self.assertEqual(result["state"], "DECLARATIONS_RECONCILED_ONLY")
        self.assertEqual(result["drift_count"], 0)
        self.assertEqual(len(result["findings"]), 6)
        self.assertFalse(result["release_authorized"])
        self.assertFalse(result["model_training_authorized"])
        self.assertTrue(all(x["runtime_source_parity"] == "UNVERIFIED" for x in result["findings"]))

    def test_terra_finance_and_counsel_heuristics_are_held(self):
        manifest, historical = fixture()
        historical = historical.replace(
            b"| terra | public | docker | RUNNING | szl-real-estate | exact |",
            b"| terra | public | docker | RUNNING | - | unbound |",
        ).replace(
            b"| finance | public | docker | RUNNING | puriq-live | exact |",
            b"| finance | public | docker | RUNNING | - | unbound |",
        ).replace(
            b"| counsel | public | docker | RUNNING | platform | exact |",
            b"| counsel | public | docker | RUNNING | counsel | exact |",
        )
        raw, pin = raw_pin(manifest)
        result = check.reconcile(raw, pin, historical)
        states = {x["space"].split("/")[-1]: x["declaration_state"] for x in result["findings"]}
        self.assertEqual(result["state"], "HOLD_REGISTRY_DRIFT")
        self.assertEqual(result["drift_count"], 3)
        self.assertEqual(states["terra"], "HOLD_HEURISTIC_UNBOUND")
        self.assertEqual(states["finance"], "HOLD_HEURISTIC_UNBOUND")
        self.assertEqual(states["counsel"], "HOLD_HEURISTIC_CONFLICT")
        self.assertFalse(result["publisher_dispatch"])

    def test_wrong_or_unpinned_manifest_bytes_denied(self):
        manifest, historical = fixture()
        raw, pin = raw_pin(manifest)
        for bad in ("", "1" * 40, "abc", None):
            with self.subTest(bad=bad), self.assertRaises(check.ContractError):
                check.reconcile(raw, bad, historical)
        with self.assertRaises(check.ContractError):
            check.reconcile(raw + b" ", pin, historical)

    def test_duplicate_json_key_denied(self):
        manifest, _ = fixture()
        raw, _ = raw_pin(manifest)
        raw = raw.replace(b'"schema": ', b'"schema": "fake", "schema": ', 1)
        pin = check._blob_sha(raw)
        with self.assertRaisesRegex(check.ContractError, "DUPLICATE_JSON_KEY"):
            check.declared_sources(raw, pin)

    def test_unknown_org_duplicate_slug_or_surface_denied(self):
        manifest, _ = fixture()
        for mutated in ("org", "duplicate_slug", "surface", "duplicate_body", "schema"):
            x = json.loads(json.dumps(manifest))
            if mutated == "org":
                x["hub_org"] = "rogue"
            elif mutated == "duplicate_slug":
                x["hub_alias_policy"]["canonical_public_space_slugs"][-1] = "a11oy"
            elif mutated == "surface":
                x["public_bodies"][0]["hub_surface"] = "OTHER/terra"
            elif mutated == "duplicate_body":
                x["public_bodies"][1]["hub_surface"] = x["public_bodies"][0]["hub_surface"]
            else:
                x["schema"] = "unknown"
            raw, pin = raw_pin(x)
            with self.subTest(mutated=mutated), self.assertRaises(check.ContractError):
                check.declared_sources(raw, pin)

    def test_ambiguous_or_nonpublic_inventory_denied(self):
        manifest, historical = fixture()
        raw, pin = raw_pin(manifest)
        duplicate = historical + b"\n| terra | public | docker | RUNNING | terra | exact |"
        with self.assertRaisesRegex(check.ContractError, "DUPLICATE_INVENTORY_SLUG"):
            check.reconcile(raw, pin, duplicate)
        nonpublic = historical.replace(
            b"| terra | public |", b"| terra | private |"
        )
        result = check.reconcile(raw, pin, nonpublic)
        self.assertEqual(result["state"], "HOLD_REGISTRY_DRIFT")
        self.assertEqual(
            next(x["declaration_state"] for x in result["findings"] if x["space"].endswith("/terra")),
            "HOLD_VISIBILITY_UNVERIFIED",
        )

    def test_historical_running_does_not_prove_operational(self):
        manifest, historical = fixture()
        raw, pin = raw_pin(manifest)
        result = check.reconcile(raw, pin, historical)
        self.assertTrue(all(x["live_route_health"] == "NOT_CHECKED" for x in result["findings"]))


if __name__ == "__main__":
    unittest.main()
