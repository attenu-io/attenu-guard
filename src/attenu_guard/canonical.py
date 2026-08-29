"""RFC 8785 JSON Canonicalization Scheme (JCS), stdlib-only.

The accepted data model is deliberately closed: exact built-in JSON types,
plus tuples as immutable JSON arrays.  Values outside that model are rejected
instead of being coerced through user-defined numeric or mapping protocols.
"""
from __future__ import annotations

import math

__all__ = [
    "CanonicalizationError",
    "LoneSurrogateError",
    "NonFiniteNumberError",
    "UnsupportedTypeError",
    "dumps",
]


class CanonicalizationError(ValueError):
    """Base class for values that cannot be represented by RFC 8785 JCS."""


class NonFiniteNumberError(CanonicalizationError):
    """A number is NaN, infinite, or outside the binary64 domain."""


class LoneSurrogateError(CanonicalizationError):
    """A string contains an unpaired UTF-16 surrogate code point."""


class UnsupportedTypeError(CanonicalizationError, TypeError):
    """A value is outside the library's closed JSON input model."""


_ESCAPES = {
    '"': '\\"',
    "\\": "\\\\",
    "\b": "\\b",
    "\f": "\\f",
    "\n": "\\n",
    "\r": "\\r",
    "\t": "\\t",
}


def _number(value: int | float) -> str:
    """ECMAScript ``Number::toString`` formatting required by RFC 8785."""
    try:
        number = float(value) if type(value) is int else value
    except OverflowError as exc:
        raise NonFiniteNumberError("integer is outside the binary64 domain") from exc
    if not math.isfinite(number):
        raise NonFiniteNumberError("non-finite numbers are not permitted")
    if number == 0:
        return "0"

    sign = "-" if number < 0 else ""
    rendered = repr(abs(number))
    if "e" in rendered or "E" in rendered:
        mantissa, exponent_text = rendered.lower().split("e", 1)
        exponent = int(exponent_text)
    else:
        mantissa, exponent = rendered, 0

    integer, dot, fraction = mantissa.partition(".")
    if not dot:
        fraction = ""
    digits = (integer + fraction).lstrip("0") or "0"
    stripped_integer = integer.lstrip("0")
    if stripped_integer:
        decimal_position = len(stripped_integer) + exponent
    else:
        decimal_position = exponent - (len(fraction) - len(fraction.lstrip("0")))
    significant = digits.rstrip("0") or "0"
    length = len(significant)

    if length <= decimal_position <= 21:
        return sign + significant + "0" * (decimal_position - length)
    if 0 < decimal_position <= 21:
        return sign + significant[:decimal_position] + "." + significant[decimal_position:]
    if -6 < decimal_position <= 0:
        return sign + "0." + "0" * (-decimal_position) + significant

    exponent = decimal_position - 1
    exponent_sign = "+" if exponent >= 0 else "-"
    head = significant[0] if length == 1 else significant[0] + "." + significant[1:]
    return sign + head + "e" + exponent_sign + str(abs(exponent))


def _string(value: str) -> str:
    out = ['"']
    for char in value:
        codepoint = ord(char)
        if 0xD800 <= codepoint <= 0xDFFF:
            raise LoneSurrogateError("lone UTF-16 surrogates are not permitted")
        escaped = _ESCAPES.get(char)
        if escaped is not None:
            out.append(escaped)
        elif codepoint < 0x20:
            out.append("\\u%04x" % codepoint)
        else:
            out.append(char)
    out.append('"')
    return "".join(out)


def _text(value) -> str:
    value_type = type(value)
    if value is None:
        return "null"
    if value_type is bool:
        return "true" if value else "false"
    if value_type is int or value_type is float:
        return _number(value)
    if value_type is str:
        return _string(value)
    if value_type is list or value_type is tuple:
        return "[" + ",".join(_text(item) for item in value) + "]"
    if value_type is dict:
        for key in value:
            if type(key) is not str:
                raise UnsupportedTypeError("JSON object member names must be exact strings")
            _string(key)  # validate lone surrogates before UTF-16 encoding/sorting
        items = sorted(value.items(), key=lambda item: item[0].encode("utf-16-be"))
        return "{" + ",".join(_string(key) + ":" + _text(item) for key, item in items) + "}"
    raise UnsupportedTypeError(f"not a supported JSON value: {value_type.__name__}")


def dumps(value) -> bytes:
    """Return the RFC 8785 canonical UTF-8 representation of ``value``."""
    return _text(value).encode("utf-8")
