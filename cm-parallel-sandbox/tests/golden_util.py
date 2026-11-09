"""Golden-file snapshot helper: set UPDATE_GOLDEN=1 to (re)write snapshots."""

import os
import pathlib

GOLDEN_DIR = pathlib.Path(__file__).resolve().parent / "golden"


def assert_golden(test, name, text):
  path = GOLDEN_DIR / name
  if os.environ.get("UPDATE_GOLDEN"):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)
    return
  test.assertTrue(path.is_file(),
                  f"missing golden {path}; regenerate with UPDATE_GOLDEN=1")
  test.maxDiff = None
  test.assertEqual(path.read_text(), text, f"golden mismatch: {name}")
