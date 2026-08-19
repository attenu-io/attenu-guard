"""tests/test_sinks_identity.py — product identity without a key; sinks/spool contract. stdlib only.

Slice 1 / Plan A, Tasks 6-7. Run: PYTHONPATH=src python3 tests/test_sinks_identity.py
"""
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))


class Identity(unittest.TestCase):
    def test_boot_id_is_stable_in_process_and_hex(self):
        from delegation_guard import identity
        a, b = identity.boot_id(), identity.boot_id()
        self.assertEqual(a, b); self.assertEqual(len(a), 16); int(a, 16)

    def test_product_is_found_by_walking_up_and_identity_needs_no_key(self):
        from delegation_guard import identity
        with tempfile.TemporaryDirectory() as d:
            root = Path(d) / "proj"; (root / ".attenu").mkdir(parents=True)
            (root / ".attenu" / "product.json").write_text(json.dumps(
                {"product_id": "01J0PRODUCT", "name": "Mortgage Assistant", "environment": "dev"}))
            nested = root / "src" / "deep"; nested.mkdir(parents=True)
            self.assertEqual(identity.find_product_dir(nested), root.resolve())
            self.assertEqual(identity.load_product(nested)["product_id"], "01J0PRODUCT")
            self.assertIsNone(identity.load_product(Path(d)))                       # outside any product: None, not an error
            os.environ["ATTENU_PRODUCT_DIR"] = str(root)
            try:
                self.assertEqual(identity.find_product_dir(Path(d)), root)          # env override wins
            finally:
                del os.environ["ATTENU_PRODUCT_DIR"]
            p = identity.ledger_path(root, "chain-ab12cd34", boot="deadbeefdeadbeef")
            self.assertEqual(p, root / ".attenu" / "ledger" / "deadbeefdeadbeef" / "chain-ab12cd34.jsonl")
            sp = identity.spool_path(root, boot="deadbeefdeadbeef")
            self.assertEqual(sp, root / ".attenu" / "spool" / "deadbeefdeadbeef.ndjson")
            cid = identity.new_chain_id("run")
            self.assertTrue(cid.startswith("run-") and len(cid) == 12)
            self.assertNotEqual(identity.new_chain_id(), identity.new_chain_id())   # assigned, never inferred


class Spool(unittest.TestCase):
    def _guard(self, sink):
        from delegation_guard import Authority, Guard
        return Guard.issue("a", Authority({"crm.read"}, [], ttl=None), task="t", audit_sinks=(sink,))

    def test_spool_is_a_separate_file_that_survives_a_new_audit_log(self):
        from delegation_guard.sinks import SpoolSink
        with tempfile.TemporaryDirectory() as d:
            sp = Path(d) / "spool.ndjson"
            g1 = self._guard(SpoolSink(sp, boot="b1")); g1.check("crm.read", tool="q"); g1.check("x.y", tool="z")
            g2 = self._guard(SpoolSink(sp, boot="b2")); g2.check("crm.read", tool="q")   # a NEW AuditLog (its own file truncates) must not truncate the spool
            lines = [json.loads(l) for l in sp.read_text().splitlines()]
            self.assertEqual(len(lines), 3 + 2)                                           # 2 roots + 3 checks
            self.assertEqual({l["boot_id"] for l in lines}, {"b1", "b2"})
            self.assertTrue(all({"boot_id", "chain_id", "seq", "hash", "entry"} <= set(l) for l in lines))   # the ingest idempotency key travels with every line
            self.assertEqual(lines[0]["entry"]["event"], "root")

    def test_spool_is_bounded_and_never_touches_the_log_of_record(self):
        from delegation_guard.sinks import SpoolSink
        with tempfile.TemporaryDirectory() as d:
            sink = SpoolSink(Path(d) / "s.ndjson", boot="b", max_bytes=600)
            g = self._guard(sink)
            for _ in range(50):
                g.check("crm.read", tool="q")
            self.assertTrue(sink.overflowed and sink.dropped > 0)
            self.assertEqual(len(g.audit_log().entries), 51)                      # ledger complete regardless
            sink.flush()
            self.assertLessEqual((Path(d) / "s.ndjson").stat().st_size, 600)

    def test_read_pending_and_ack_are_resumable(self):
        from delegation_guard.sinks import SpoolSink
        with tempfile.TemporaryDirectory() as d:
            sp = Path(d) / "s.ndjson"; sink = SpoolSink(sp, boot="b"); g = self._guard(sink)
            for _ in range(5): g.check("crm.read", tool="q")
            sink.flush()
            batch = sink.read_pending(max_n=3); self.assertEqual([b["seq"] for b in batch], [0, 1, 2]); sink.ack(3)
            again = SpoolSink(sp, boot="b")                                        # a fresh uploader process resumes from the offset file
            self.assertEqual([b["seq"] for b in again.read_pending()], [3, 4, 5])

    def test_fsync_happens_on_flush_and_every_n_writes(self):
        import os as _os
        from delegation_guard import sinks
        calls = []
        real = _os.fsync
        _os.fsync = lambda fd: calls.append(fd)
        try:
            with tempfile.TemporaryDirectory() as d:
                sink = sinks.SpoolSink(Path(d) / "s.ndjson", boot="b", fsync_every=2); g = self._guard(sink)
                g.check("crm.read", tool="q")                      # root + allow = 2 writes -> one fsync
                self.assertEqual(len(calls), 1)
                sink.flush()
                self.assertEqual(len(calls), 2)
        finally:
            _os.fsync = real

    def test_sink_never_imports_the_network(self):
        import delegation_guard.sinks as sinks_mod
        src = Path(sinks_mod.__file__).read_text()
        for banned in ("socket", "urllib", "http.client", "requests", "httpx"):
            self.assertNotIn(f"import {banned}", src)


if __name__ == "__main__":
    unittest.main(verbosity=2)
