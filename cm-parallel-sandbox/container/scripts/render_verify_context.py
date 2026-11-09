#!/usr/bin/env python3
"""Renders config/verify_context.md with a live, in-container tool inventory."""

import argparse
import os
import shutil
import string
import subprocess
import sys

TOOLS = ("python3", "node", "go", "gcc", "g++", "make", "javac", "java", "php",
         "ruby", "sqlite3", "git", "curl")


def _first_line(cmd):
  try:
    p = subprocess.run(cmd, capture_output=True, text=True, timeout=20)
  except (OSError, subprocess.TimeoutExpired):
    return ""
  out = ((p.stdout or "") + (p.stderr or "")).strip()
  return out.splitlines()[0] if out else ""


def tool_inventory():
  """Mirrors the VERIFY_AIRGAP.md §1 shell inventory loop."""
  lines = []
  for t in TOOLS:
    if shutil.which(t):
      lines.append(f"   - {t}: {_first_line([t, '--version'])}")
  pip = subprocess.run([sys.executable, "-m", "pip", "list", "--format=freeze"],
                       capture_output=True, text=True)
  pkgs = " ".join(pip.stdout.split()) if pip.returncode == 0 else ""
  lines.append(f"   - python packages (offline): {pkgs}")
  root = _first_line(["npm", "root", "-g"]) if shutil.which("npm") else ""
  mods = " ".join(sorted(os.listdir(root))) if root and os.path.isdir(root) else ""
  lines.append(f"   - node global modules (offline): {mods}")
  return "\n".join(lines)


def render(template_text, repo_dir, repo_id, language, inventory):
  """string.Template.substitute raises KeyError on any unknown $PLACEHOLDER."""
  return string.Template(template_text).substitute(
      REPO_DIR=repo_dir, REPO_ID=repo_id, LANGUAGE=language or "unknown",
      TOOL_INVENTORY=inventory)


def main(argv=None):
  p = argparse.ArgumentParser(description=__doc__)
  p.add_argument("--template", default="")
  p.add_argument("--repo-dir", default="")
  p.add_argument("--repo-id", default="")
  p.add_argument("--language", default="")
  p.add_argument("--finding-id", default="")
  p.add_argument("--inventory-file", default="",
                 help="reuse a precomputed inventory instead of probing tools")
  p.add_argument("--inventory-only", action="store_true",
                 help="print only the tool inventory")
  a = p.parse_args(argv)
  if a.inventory_file and os.path.exists(a.inventory_file):
    with open(a.inventory_file) as f:
      inv = f.read().rstrip("\n")
  else:
    inv = tool_inventory()
  if a.inventory_only:
    print(inv)
    return 0
  if not (a.template and a.repo_dir and a.repo_id):
    p.error("--template, --repo-dir and --repo-id are required")
  with open(a.template) as f:
    sys.stdout.write(render(f.read(), a.repo_dir, a.repo_id, a.language, inv))
  return 0


if __name__ == "__main__":
  sys.exit(main())
