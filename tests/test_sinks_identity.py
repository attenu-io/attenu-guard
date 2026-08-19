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


if __name__ == "__main__":
    unittest.main(verbosity=2)
