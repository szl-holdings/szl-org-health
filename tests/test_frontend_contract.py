import unittest
from pathlib import Path


class FrontendContractTests(unittest.TestCase):
    def test_structured_space_hardware_is_rendered_explicitly(self):
        html = Path("static/index.html").read_text(encoding="utf-8")

        self.assertIn("function hardwareLabel(hardware)", html)
        self.assertIn("hardware.current", html)
        self.assertIn("hardware.requested", html)
        self.assertIn("hardwareLabel(space.hardware)", html)
        self.assertNotIn("[space.sdk,space.hardware,space.sha", html)

    def test_space_reachability_is_not_presented_as_operational_proof(self):
        html = Path("static/index.html").read_text(encoding="utf-8")

        self.assertIn("REACHABLE_UNVERIFIED", html)
        self.assertIn("OPERATIONAL_SOURCE_BOUND", html)
        self.assertIn("space.source_binding_state", html)
        self.assertIn("space.healthz===200", html)
        self.assertNotIn("running_spaces===s.spaces?'ok'", html)

    def test_first_class_kernels_and_bucket_contracts_are_visible(self):
        html = Path("static/index.html").read_text(encoding="utf-8")

        self.assertIn("HF Kernels", html)
        self.assertIn("Hugging Face Kernels", html)
        self.assertIn("kernel.contract_state", html)
        self.assertIn("selfcheck not executed", html)
        self.assertIn("b.documentation_state", html)


if __name__ == "__main__":
    unittest.main()
