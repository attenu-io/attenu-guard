"""The poisoned-summariser demo — runnable from a clone without installing.

The demo itself lives in the package (`attenu_guard._demo`) so that
`attenu-guard demo` works from an installed wheel; this file only makes
`python examples/poisoned_summarizer.py` work from a fresh checkout.
"""
import sys as _sys
import pathlib as _pathlib
try:
    import attenu_guard  # noqa: F401
except ImportError:  # running from a clone without install
    _sys.path.insert(0, str(_pathlib.Path(__file__).resolve().parents[1] / "src"))
from attenu_guard._demo import main  # noqa: E402

if __name__ == "__main__":
    main()
