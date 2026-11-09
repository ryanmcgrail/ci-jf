"""Tests for container/scripts/render_verify_context.py (VERIFY_AIRGAP.md §6)."""

import importlib.util
import pathlib
import re
import unittest

ROOT = pathlib.Path(__file__).resolve().parent.parent
TEMPLATE = (ROOT / "config" / "verify_context.md").read_text()
_spec = importlib.util.spec_from_file_location(
    "render_verify_context", ROOT / "container" / "scripts" / "render_verify_context.py")
rvc = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(rvc)

INV = "   - python3: Python 3.12.3\n   - python packages (offline): flask==3.0.3"


class RenderTest(unittest.TestCase):

  def render(self):
    return rvc.render(TEMPLATE, "/home/runner/workspace/o04-vampi", "o04-vampi",
                      "python", INV)

  def test_all_vars_substituted(self):
    out = self.render()
    self.assertNotIn("$", out)
    self.assertNotIn("$REPO_DIR", out)
    self.assertIn("/home/runner/workspace/o04-vampi is a depth-1 source checkout "
                  "of o04-vampi (primary language: python)", out)

  def test_inventory_injected(self):
    out = self.render()
    self.assertTrue(out.rstrip().endswith("flask==3.0.3"))
    self.assertIn("   - python3: Python 3.12.3", out)

  def test_template_has_exactly_sections_1_to_4(self):
    sections = re.findall(r"^(\d+)\. [A-Z]", TEMPLATE, flags=re.M)
    self.assertEqual(sections, ["1", "2", "3", "4"])
    self.assertTrue(TEMPLATE.startswith(
        "IMPORTANT: EXECUTION ENVIRONMENT CONSTRAINTS (read before planning)"))
    self.assertTrue(TEMPLATE.rstrip().endswith("$TOOL_INVENTORY"))

  def test_unknown_placeholder_raises(self):
    with self.assertRaises(KeyError):
      rvc.render(TEMPLATE + "\n$BOGUS\n", "/r", "id", "py", INV)

  def test_live_inventory_lists_python(self):
    inv = rvc.tool_inventory()
    self.assertIn("   - python3: Python 3", inv)
    self.assertIn("   - python packages (offline): ", inv)
    self.assertIn("   - node global modules (offline): ", inv)


if __name__ == "__main__":
  unittest.main()
