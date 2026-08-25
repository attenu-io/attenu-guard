#!/usr/bin/env python3
"""The hook Claude Code runs in this sample project.

In your own project, put the recipe's `hook.py` in this directory and point the
`command` in settings.json at it. Here it is a wrapper rather than a copy, so the code
a reader reviews is the code this project runs: it looks for `hook.py` beside itself
first (the normal install), then in the recipe directory this sample ships inside.
"""
import pathlib
import sys

_here = pathlib.Path(__file__).resolve().parent
for _candidate in (_here, _here.parents[2]):
    if (_candidate / "hook.py").is_file():
        sys.path.insert(0, str(_candidate))
        break
else:  # pragma: no cover - only when the recipe is installed somewhere unexpected
    sys.stderr.write("attenu-guard: hook.py not found next to attenu_hook.py\n")
    raise SystemExit(2)

from hook import main  # noqa: E402

if __name__ == "__main__":
    sys.exit(main())
