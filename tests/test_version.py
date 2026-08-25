"""The package version and pyproject must agree — a rename/release bump that misses one is a public embarrassment."""
import re
from pathlib import Path


def test_version_matches_pyproject():
    import attenu_guard
    toml = (Path(__file__).resolve().parents[1] / "pyproject.toml").read_text()
    assert re.search(r'^version = "([^"]+)"', toml, re.M).group(1) == attenu_guard.__version__
