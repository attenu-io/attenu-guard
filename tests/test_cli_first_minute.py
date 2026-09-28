"""The first minute of the README, run as written: the quickstart, `attenu-guard view` on the
log it writes, the observe-mode snippet, the demo, and the empty ledger that must not verify."""
from __future__ import annotations

import contextlib
import io
import json
import os
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from attenu_guard import cli, evidence  # noqa: E402

README = (ROOT / "README.md").read_text(encoding="utf-8")
SAMPLES = ROOT / "examples" / "verify"


def run(*args) -> tuple[int, str]:
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        rc = cli.main(list(args))
    return rc, out.getvalue()


def blocks(text: str) -> list[tuple[str, str]]:
    """Every fenced block in order, as (language, body)."""
    return [(m.group(1), m.group(2)) for m in re.finditer(r"^```(\w*)\n(.*?)^```$", text, re.S | re.M)]


def run_snippet(code: str, cwd: str) -> str:
    env = dict(os.environ, PYTHONPATH=str(ROOT / "src"), PYTHONIOENCODING="utf-8")
    proc = subprocess.run([sys.executable, "-c", code], cwd=cwd, env=env,
                          capture_output=True, text=True, encoding="utf-8", timeout=60)
    assert proc.returncode == 0, proc.stderr
    return proc.stdout


class TestEmptyLedger(unittest.TestCase):
    def _ledger(self, content: str) -> str:
        d = tempfile.mkdtemp()
        p = Path(d) / "log.jsonl"
        p.write_text(content, encoding="utf-8")
        return str(p)

    def test_verify_zero_byte_ledger_is_empty_not_ok(self):
        rc, out = run("verify", self._ledger(""))
        self.assertEqual(rc, 2, out)
        self.assertIn("EMPTY", out)
        self.assertNotEqual(out.strip(), "OK")

    def test_verify_blank_lines_only_ledger_is_empty_not_ok(self):
        rc, out = run("verify", self._ledger("\n\n  \n"))
        self.assertEqual(rc, 2, out)
        self.assertIn("EMPTY", out)

    def test_view_zero_byte_ledger_is_empty_not_ok(self):
        rc, out = run("view", self._ledger(""))
        self.assertEqual(rc, 2, out)
        self.assertIn("EMPTY", out)
        self.assertNotIn("verification: OK", out)

    def test_bundle_with_zero_entries_is_refused(self):
        bundle = json.loads((SAMPLES / "clean.bundle.json").read_text())
        bundle["entries"] = []
        rep = evidence.verify_bundle(bundle)
        self.assertFalse(rep["ok"])
        self.assertTrue(any(f.startswith("missing_root") for f in rep["failures"]), rep["failures"])
        p = Path(tempfile.mkdtemp()) / "empty.bundle.json"
        p.write_text(json.dumps(bundle), encoding="utf-8")
        rc, out = run("verify", str(p))
        self.assertEqual(rc, 2, out)
        self.assertIn("FAILED", out)


class TestDemo(unittest.TestCase):
    def test_demo_banner_does_not_claim_no_rule_was_written(self):
        # The demo declares the summariser's Authority by hand; the banner must not say otherwise.
        rc, out = run("demo")
        self.assertEqual(rc, 0)
        self.assertNotIn("No rule was written", out)
        self.assertIn("attenu-guard demo --audit-path", out)

    def test_demo_audit_path_writes_a_ledger_view_renders_with_a_denial(self):
        path = str(Path(tempfile.mkdtemp()) / "demo.jsonl")
        rc, out = run("demo", "--audit-path", path)
        self.assertEqual(rc, 0, out)
        self.assertIn(f"attenu-guard view {path}", out)
        rc, view = run("view", path)
        self.assertEqual(rc, 0, view)
        self.assertIn("✗", view)
        self.assertIn("verification: OK", view)

    def test_demo_accepts_the_equals_form_of_audit_path(self):
        # `--audit-path=FILE` used to be ignored silently: exit 0, no file, generic hint.
        path = str(Path(tempfile.mkdtemp()) / "demo.jsonl")
        rc, _ = run("demo", f"--audit-path={path}")
        self.assertEqual(rc, 0)
        self.assertTrue(Path(path).is_file())

    def test_demo_rejects_an_unknown_argument_instead_of_ignoring_it(self):
        rc, out = run("demo", "--audit-pth", "x.jsonl")
        self.assertEqual(rc, 1)
        self.assertIn("unknown argument: --audit-pth", out)
        self.assertIn("usage: attenu-guard demo", out)

    def test_demo_names_a_directory_or_file_parent_as_not_a_file_path(self):
        d = tempfile.mkdtemp()
        rc, out = run("demo", "--audit-path", d)
        self.assertEqual(rc, 1)
        self.assertIn("is not a file path", out)
        self.assertNotIn("already holds a ledger", out)
        blocker = Path(d) / "afile"
        blocker.write_text("x")
        rc, out = run("demo", "--audit-path", str(blocker / "demo.jsonl"))
        self.assertEqual(rc, 1)
        self.assertIn("is not a file path", out)

    def test_demo_refuses_to_overwrite_an_existing_ledger(self):
        path = str(Path(tempfile.mkdtemp()) / "demo.jsonl")
        self.assertEqual(run("demo", "--audit-path", path)[0], 0)
        rc, out = run("demo", "--audit-path", path)
        self.assertEqual(rc, 1)
        self.assertIn("will not overwrite", out)


class TestExistingLedgerMessage(unittest.TestCase):
    def test_existing_ledger_error_names_the_keyword_guard_issue_accepts(self):
        # The message used to say "pass overwrite=True"; Guard.issue(overwrite=True) is a TypeError.
        from attenu_guard import Authority, Guard
        path = str(Path(tempfile.mkdtemp()) / "log.jsonl")
        auth = Authority(scopes={"crm.read"}, ceilings=[], ttl=60)
        Guard.issue("a", auth, audit_path=path)
        with self.assertRaises(FileExistsError) as cm:
            Guard.issue("a", auth, audit_path=path)
        self.assertIn("audit_overwrite=True", str(cm.exception))
        Guard.issue("a", auth, audit_path=path, audit_overwrite=True)  # the named keyword works


class TestReadmeSnippetsPrintWhatTheReadmeShows(unittest.TestCase):
    def test_quickstart_output_and_view_output_match_the_readme(self):
        bs = blocks(README)
        i = next(n for n, (lang, _) in enumerate(bs) if lang == "python")
        code, printed = bs[i][1], bs[i + 1][1]
        self.assertIn('audit_path="log.jsonl"', code)
        self.assertEqual(bs[i + 2], ("bash", "attenu-guard view log.jsonl\n"))
        shown_view = bs[i + 3][1]
        with tempfile.TemporaryDirectory() as d:
            self.assertEqual(run_snippet(code, d), printed)
            rc, view = run("view", str(Path(d) / "log.jsonl"))
        self.assertEqual(rc, 0)
        self.assertEqual(view, shown_view)

    def test_observe_mode_output_matches_the_readme(self):
        section = README.split("## Observe mode", 1)[1]
        bs = blocks(section)
        self.assertEqual(bs[0][0], "python")
        with tempfile.TemporaryDirectory() as d:
            self.assertEqual(run_snippet(bs[0][1], d), bs[1][1])


if __name__ == "__main__":
    unittest.main()
