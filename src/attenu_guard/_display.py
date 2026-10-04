"""
How a value from a ledger or a bundle is printed into a line of text.

A ledger, a bundle and the envelopes beside it are untrusted input, and their values reach a
terminal through the verifier's finding messages, `attenu-guard verify`, and `--entries`. A value
that carries a line break can end the line it is printed on and start a forged one: a node named
"n1\\nOK" would print a line reading `OK` under a failed verification. One rule covers every place
such a value is printed without quotes:

  * a value whose text is entirely printable ASCII 0x21-0x7E other than `"` and `\\` prints as
    that text, exactly as it always has, so clean input prints byte for byte as before;
  * any other value prints as its JSON form, with every character outside printable ASCII
    escaped as \\uXXXX (UTF-16 code units, lower-case hex) and every space as \\u0020. That form
    holds no whitespace and no line break, and `json.loads` gives the value back.

A value printed through `repr` (`{x!r}`) is quoted and escaped already, and is left alone.
"""
from __future__ import annotations

import json
import re

#: The bare form: printable ASCII 0x21-0x7E without `"` (0x22) or `\` (0x5C).
BARE = re.compile(r'[!#-\[\]-~]+')


def escaped(value) -> str:
    """`value` as whitespace-free, ASCII-only JSON.

    `ensure_ascii` escapes everything outside printable ASCII, and the space is the one printable
    character JSON leaves alone; a value that is not JSON-native is rendered through `str`."""
    return json.dumps(value, ensure_ascii=True, separators=(",", ":"),
                      default=str).replace(" ", "\\u0020")


def shown(value) -> str:
    """`value` as a finding message prints it: the text it has always printed as (`str`) when
    that text is bare, its `escaped` JSON form otherwise."""
    text = value if isinstance(value, str) else str(value)
    return text if BARE.fullmatch(text) else escaped(value)
