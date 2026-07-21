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


if __name__ == "__main__":
    unittest.main()
