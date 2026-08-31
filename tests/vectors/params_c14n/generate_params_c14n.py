"""
tests/vectors/generate_params_c14n.py — deterministic, language-neutral parity vectors for the
`params_c14n_v1` argument commitment (docs/execution-binding spec section 4;
attenu_guard.params.commit()): `SHA-256(raw_salt || UTF8(JCS(params)))`.

This is a SEPARATE, smaller vector suite from tests/vectors/generate.py's Delegation Token
(wire.py) vectors — params_c14n_v1 is a different contract (a hash function over one JSON value
plus a salt, not a signed chain of tokens), so it gets its own file rather than being force-fit
into that generator's shape. A TypeScript implementation of params_c14n_v1 is meant to consume
this SAME file (no Python required): for each case, decode `salt_hex` to 16 raw bytes, compute
the commitment (or confirm the value is outside the domain), and compare against `expect`.

stdlib-only, runnable with bare `python3`, no network, no randomness:

    python3 tests/vectors/generate_params_c14n.py

Deterministic: every run produces byte-identical output. tests/test_params_c14n_vectors.py
self-checks every case against this build's attenu_guard.params.commit() on every CI run.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(_ROOT / "src"))

from attenu_guard import canonical, params as params_mod  # noqa: E402

VECTORS_DIR = Path(__file__).resolve().parent
OUT_FILE = VECTORS_DIR / "params_c14n_v1.json"

# Two fixed, published salts — deliberately NOT secrets (this is an interop vector file). Salt A
# is used for most cases; salt B exists only to exercise "same params, different salt -> a
# different commitment" (params_c14n_v1's whole reason for having a salt at all).
SALT_A_HEX = "0011223344556677" * 2  # 32 hex chars = 16 bytes
SALT_B_HEX = "ffeeddccbbaa9988" * 2


def _case(name: str, description: str, params, salt_hex: str = SALT_A_HEX) -> dict:
    raw_salt = params_mod.decode_salt(salt_hex)
    hash_hex, reason = params_mod.commit(params, raw_salt)
    entry = {
        "name": name,
        "description": description,
        "salt_hex": salt_hex,
        "params": params,
    }
    if hash_hex is not None:
        entry["expect"] = "hash"
        entry["hash_hex"] = hash_hex
    else:
        entry["expect"] = "unsupported"
        assert reason == params_mod.ParamsHashReason.UNSUPPORTED
    return entry


def generate() -> dict:
    max_safe = canonical.MAX_SAFE_INTEGER
    cases = [
        _case("safe_integer_boundary_accept",
             "The largest safe integer (2**53-1) — the last value a binary64 double still "
             "represents exactly.",
             {"n": max_safe}),
        _case("one_past_safe_boundary_reject",
             "One magnitude past the safe boundary — rejected as unsupported, not silently "
             "rounded.",
             {"n": max_safe + 1}),
        _case("nine_e15_accept",
             "9e15 as a float: below the safe-integer bound, so it is a supported integral "
             "float.",
             {"n": 9e15}),
        _case("one_e16_reject",
             "1e16 as a float: an integral value beyond the safe-integer bound. Unlike the "
             "general JCS signing surface (audit hashes, wire tokens), which tolerates this "
             "(see tests/test_canonical.py's pinned divergence-class vector), params_c14n_v1 "
             "does not: a cross-runtime consumer (JSON/JS has no int/float distinction) cannot "
             "tell an out-of-range Python int from an out-of-range float once serialized.",
             {"n": 1e16}),
        _case("negative_integer_boundary_accept",
             "The negative safe-integer boundary.",
             {"n": -max_safe}),
        _case("negative_one_past_boundary_reject",
             "One magnitude past the negative safe boundary.",
             {"n": -(max_safe + 1)}),
        _case("positive_zero_accept",
             "Positive zero.",
             {"n": 0.0}),
        _case("negative_zero_accept",
             "Negative zero — MUST hash identically to positive_zero_accept (same params_c14n_v1 "
             "input under RFC 8785 JCS, which renders both as \"0\").",
             {"n": -0.0}),
        _case("ordinary_nested_object_accept",
             "A representative structured tool-call argument object: nested objects, an array, "
             "a string, a bool, and null.",
             {"query": "customers where plan = 'pro'", "limit": 50, "filters": {"active": True, "region": None},
              "tags": ["billing", "renewal"]}),
        _case("salt_a_accept",
             "Same params as salt_b_accept, salt A -- the two MUST produce DIFFERENT hash_hex "
             "values (the salt is what prevents linking argument equality across chains).",
             {"tool": "crm.read", "rows": 100}, salt_hex=SALT_A_HEX),
        _case("salt_b_accept",
             "Same params as salt_a_accept, salt B -- see salt_a_accept.",
             {"tool": "crm.read", "rows": 100}, salt_hex=SALT_B_HEX),
    ]
    assert cases[6]["name"] == "positive_zero_accept" and cases[7]["name"] == "negative_zero_accept"
    assert cases[6]["hash_hex"] == cases[7]["hash_hex"], "negative zero must hash identically to positive zero"
    assert cases[9]["name"] == "salt_a_accept" and cases[10]["name"] == "salt_b_accept"
    assert cases[9]["hash_hex"] != cases[10]["hash_hex"], "different salts must diverge for identical params"

    return {
        "description": "Language-neutral parity vectors for params_c14n_v1 (docs/execution-binding "
                       "spec section 4): SHA-256(raw_salt || UTF8(JCS(params))). salt_hex is 32 "
                       "lowercase hex characters (16 raw bytes). For each case: decode salt_hex, "
                       "canonicalize params per RFC 8785 JCS, and either compute the SHA-256 "
                       "commitment (expect: \"hash\", compare to hash_hex) or confirm params is "
                       "outside the params_c14n_v1 domain (expect: \"unsupported\"). Malformed-salt "
                       "handling (wrong length) is exercised separately, in "
                       "tests/test_params_c14n_vectors.py, since it is a precondition failure, not "
                       "a params_c14n_v1 case.",
        "algorithm": "params_c14n_v1",
        "cases": cases,
    }


def main() -> int:
    data = generate()
    text = json.dumps(data, indent=2, sort_keys=True) + "\n"
    OUT_FILE.write_text(text)
    print(f"wrote {len(data['cases'])} case(s) to {OUT_FILE.relative_to(_ROOT)}")

    # Self-check: reload from disk and re-verify against this build's params.commit().
    reloaded = json.loads(OUT_FILE.read_text())
    ok = True
    for case in reloaded["cases"]:
        raw_salt = params_mod.decode_salt(case["salt_hex"])
        hash_hex, reason = params_mod.commit(case["params"], raw_salt)
        if case["expect"] == "hash":
            status = "OK" if hash_hex == case["hash_hex"] else "MISMATCH"
        else:
            status = "OK" if hash_hex is None else "MISMATCH"
        ok = ok and (status == "OK")
        print(f"  self-check {case['name']}: expect={case['expect']!r}  [{status}]")
    print("ALL VECTORS SELF-CONSISTENT" if ok else "VECTOR SELF-CHECK FAILED")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
