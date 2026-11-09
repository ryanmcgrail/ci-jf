"""Tests for container/scripts/import_findings.py."""

import importlib.util
import json
import pathlib
import sqlite3
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parent.parent
FIXTURE = ROOT / "tests" / "fixtures" / "findings.json"
_spec = importlib.util.spec_from_file_location(
    "import_findings", ROOT / "container" / "scripts" / "import_findings.py")
imp = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(imp)

CM090_FINDINGS = """CREATE TABLE findings (finding_id TEXT PRIMARY KEY,
  session_id TEXT NOT NULL, title TEXT, file_path TEXT, severity TEXT,
  confidence INTEGER, analysis TEXT, snippet TEXT, vuln_type TEXT, vuln_id TEXT,
  verified INTEGER DEFAULT 0, muted INTEGER DEFAULT 0, mute_reason TEXT,
  created_at TEXT NOT NULL, status TEXT DEFAULT 'OPEN')"""


class ImportFindingsTest(unittest.TestCase):

  def setUp(self):
    self.tmp = pathlib.Path(tempfile.mkdtemp())
    self.db = self.tmp / ".codemender" / "state.db"
    self.ids = self.tmp / "ids.txt"

  def run_main(self, severity="CRITICAL,HIGH"):
    imp.main(["--findings", str(FIXTURE), "--repo-dir", "/w/o04-vampi",
              "--repo-id", "o04-vampi", "--severity", severity,
              "--db-path", str(self.db), "--ids-out", str(self.ids)])
    return self.ids.read_text().split()

  def test_severity_filter_and_order(self):
    ids = self.run_main()
    fx = json.loads(FIXTURE.read_text())
    want = [f["finding_id"] for f in fx if f["severity"] == "CRITICAL"] + \
           [f["finding_id"] for f in fx if f["severity"] == "HIGH"]
    self.assertEqual(ids, want)

  def test_medium_only(self):
    self.assertEqual(len(self.run_main("medium")), 1)

  def test_paths_normalized_and_status_open(self):
    self.run_main()
    rows = sqlite3.connect(self.db).execute(
        "select file_path, status, session_id from findings").fetchall()
    self.assertEqual(len(rows), 3)
    for fp, status, _ in rows:
      self.assertTrue(fp.startswith("/w/o04-vampi/"), fp)
      self.assertNotIn("/home/runner/workspace", fp)
      self.assertEqual(status, "OPEN")
    sess = sqlite3.connect(self.db).execute(
        "select session_type, project_root from sessions").fetchall()
    self.assertEqual(sess, [("FIND", "/w/o04-vampi")])

  def test_respects_existing_cm_schema(self):
    self.db.parent.mkdir(parents=True)
    c = sqlite3.connect(self.db)
    c.execute(CM090_FINDINGS)
    c.commit()
    c.close()
    self.run_main()
    cols = [r[1] for r in sqlite3.connect(self.db).execute("PRAGMA table_info(findings)")]
    self.assertNotIn("finding_json", cols)
    self.assertEqual(sqlite3.connect(self.db).execute(
        "select count(*) from findings").fetchone()[0], 3)

  def test_null_findings(self):
    p = self.tmp / "null.json"
    p.write_text("null")
    self.assertEqual(imp.load_items(p), [])

  def test_normalize_path(self):
    self.assertEqual(imp.normalize_path("/home/runner/workspace/r/a/b.py", "r", "/x"),
                     "/x/a/b.py")
    self.assertEqual(imp.normalize_path("/tmp/foo/r/c.py", "r", "/x"), "/x/c.py")
    self.assertEqual(imp.normalize_path("rel/d.py", "r", "/x"), "/x/rel/d.py")

  def test_verify_report_only_verified_default(self):
    vrep = self.tmp / "post_verify_report.json"
    vrep.write_text(json.dumps([
        {"finding_id": "3e84cd12-afc1-508b-959e-e58c3b19e556", "status": "VERIFIED"},
        {"finding_id": "16dbc47c-637d-56fa-aef1-18f3db99ce5e", "status": "DISMISSED"},
        {"finding_id": "e4462a0a-ef85-497c-a22b-b034fe9395f3", "status": "OPEN"},
    ]))
    imp.main(["--findings", str(FIXTURE), "--repo-dir", "/w/o04-vampi",
              "--repo-id", "o04-vampi", "--severity", "CRITICAL,HIGH",
              "--verify-report", str(vrep), "--only-verified",
              "--db-path", str(self.db), "--ids-out", str(self.ids)])
    ids = self.ids.read_text().split()
    self.assertEqual(ids, ["3e84cd12-afc1-508b-959e-e58c3b19e556"])

  def test_verify_report_include_unverified_excludes_dismissed(self):
    vrep = self.tmp / "post_verify_report.json"
    vrep.write_text(json.dumps([
        {"finding_id": "3e84cd12-afc1-508b-959e-e58c3b19e556", "status": "VERIFIED"},
        {"finding_id": "16dbc47c-637d-56fa-aef1-18f3db99ce5e", "status": "DISMISSED"},
        {"finding_id": "e4462a0a-ef85-497c-a22b-b034fe9395f3", "status": "OPEN"},
    ]))
    imp.main(["--findings", str(FIXTURE), "--repo-dir", "/w/o04-vampi",
              "--repo-id", "o04-vampi", "--severity", "CRITICAL,HIGH",
              "--verify-report", str(vrep),
              "--db-path", str(self.db), "--ids-out", str(self.ids)])
    ids = self.ids.read_text().split()
    self.assertEqual(ids, [
        "3e84cd12-afc1-508b-959e-e58c3b19e556",
        "e4462a0a-ef85-497c-a22b-b034fe9395f3",
    ])

  def test_attempted_ids_boundary_enforced(self):
    att = self.tmp / "attempted_ids.txt"
    att.write_text("3e84cd12-afc1-508b-959e-e58c3b19e556\n")
    imp.main(["--findings", str(FIXTURE), "--repo-dir", "/w/o04-vampi",
              "--repo-id", "o04-vampi", "--severity", "CRITICAL,HIGH",
              "--attempted-ids", str(att),
              "--db-path", str(self.db), "--ids-out", str(self.ids)])
    ids = self.ids.read_text().split()
    self.assertEqual(ids, ["3e84cd12-afc1-508b-959e-e58c3b19e556"])

  def test_finding_ids_filter_bypasses_severity(self):
    imp.main(["--findings", str(FIXTURE), "--repo-dir", "/w/o04-vampi",
              "--repo-id", "o04-vampi", "--severity", "CRITICAL,HIGH",
              "--finding-ids", "1b1da3bb,1e9d94bf",
              "--db-path", str(self.db), "--ids-out", str(self.ids)])
    ids = self.ids.read_text().split()
    self.assertEqual(ids, [
        "1b1da3bb-4574-5a47-840b-917b3ea83716",
        "1e9d94bf-fea0-5789-928f-f691d8676a75",
    ])

  def test_exploits_dir_registers_verify_session_and_nested_artifacts(self):
    fid = "3e84cd12-afc1-508b-959e-e58c3b19e556"
    exploits = self.tmp / "exploits"
    f_exploit_dir = exploits / fid
    (f_exploit_dir / "shims" / "connexion").mkdir(parents=True)
    (f_exploit_dir / "shims" / "jsonschema").mkdir(parents=True)
    (f_exploit_dir / "exploit.sh").write_text("#!/bin/bash\nexit 0\n")
    (f_exploit_dir / "shims" / "connexion" / "__init__.py").write_text("# conn shim\n")
    (f_exploit_dir / "shims" / "jsonschema" / "__init__.py").write_text("# json shim\n")

    art_root = self.tmp / "artifacts"
    imp.main(["--findings", str(FIXTURE), "--repo-dir", "/w/o04-vampi",
              "--repo-id", "o04-vampi", "--severity", "CRITICAL,HIGH",
              "--exploits-dir", str(exploits), "--artifacts-root", str(art_root),
              "--db-path", str(self.db), "--ids-out", str(self.ids)])

    conn = sqlite3.connect(self.db)
    sess_row = conn.execute(
        "SELECT session_id, pipeline_mode, target FROM sessions WHERE session_id = ?",
        (f"sess_verify_{fid[:8]}",)).fetchone()
    self.assertIsNotNone(sess_row)
    self.assertEqual(sess_row[1], "VERIFY")
    self.assertEqual(sess_row[2], fid)

    art_rows = conn.execute(
        "SELECT filename, original_path, purpose FROM artifacts WHERE session_id = ? ORDER BY filename",
        (f"sess_verify_{fid[:8]}",)).fetchall()
    self.assertEqual(len(art_rows), 3)
    self.assertEqual(art_rows[0],
                     ("exploit.sh", "/w/o04-vampi/.exploit/exploit.sh",
                      "Exploit artifact collected from .exploit directory"))
    self.assertEqual(art_rows[1],
                     ("shims/connexion/__init__.py",
                      "/w/o04-vampi/.exploit/shims/connexion/__init__.py",
                      "Exploit artifact collected from .exploit directory"))
    self.assertEqual(art_rows[2],
                     ("shims/jsonschema/__init__.py",
                      "/w/o04-vampi/.exploit/shims/jsonschema/__init__.py",
                      "Exploit artifact collected from .exploit directory"))

    # Assert files exist in artifacts root preserving relative path
    sess_dest = art_root / f"sess_verify_{fid[:8]}"
    self.assertTrue((sess_dest / "exploit.sh").is_file())
    self.assertTrue((sess_dest / "shims" / "connexion" / "__init__.py").is_file())
    self.assertTrue((sess_dest / "shims" / "jsonschema" / "__init__.py").is_file())

    f_row = conn.execute(
        "SELECT verified, status FROM findings WHERE finding_id = ?",
        (fid,)).fetchone()
    self.assertEqual(f_row, (1, "VERIFIED"))
    conn.close()


if __name__ == "__main__":
  unittest.main()
