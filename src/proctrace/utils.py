"""Small formatting helpers shared by the renderers."""

from __future__ import annotations

import datetime as _dt
import os
import time
from typing import Optional


def sanitize(text: str, limit: Optional[int] = None) -> str:
    """Make an arbitrary path/command safe for a single terminal line.

    File names may contain newlines, tabs, ANSI escapes, or surrogate
    escapes.  Keep the text readable but never let it control the terminal.
    """
    if not text:
        return ""
    out = []
    for ch in text:
        code = ord(ch)
        if ch == "\n":
            out.append("\\n")
        elif ch == "\r":
            out.append("\\r")
        elif ch == "\t":
            out.append("\\t")
        elif ch == "\x1b":
            out.append("\\e")
        elif code < 0x20 or code == 0x7F:
            out.append("\\x%02x" % code)
        elif 0xD800 <= code <= 0xDFFF:
            out.append("\\x%02x" % (code & 0xFF))
        else:
            out.append(ch)
    value = "".join(out)
    if limit is not None and len(value) > limit:
        if limit <= 1:
            return value[:limit]
        return value[: limit - 1] + "\u2026"
    return value


def tail_fit(text: str, width: int) -> str:
    """Truncate from the left, keeping the end of a path visible."""
    if width <= 0:
        return ""
    if len(text) <= width:
        return text
    if width <= 3:
        return text[-width:]
    return "..." + text[-(width - 3):]


def head_fit(text: str, width: int) -> str:
    if width <= 0:
        return ""
    if len(text) <= width:
        return text
    if width <= 1:
        return text[:width]
    return text[: width - 1] + "\u2026"


def format_clock(ts: float, milliseconds: bool = True) -> str:
    dt = _dt.datetime.fromtimestamp(ts)
    if milliseconds:
        return dt.strftime("%H:%M:%S.") + "%03d" % (dt.microsecond // 1000)
    return dt.strftime("%H:%M:%S")


def format_datetime(ts: float) -> str:
    return _dt.datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S")


def elapsed_text(seconds: float) -> str:
    seconds = max(0.0, seconds)
    if seconds < 60:
        return "%.1fs" % seconds
    minutes, sec = divmod(int(seconds), 60)
    hours, minutes = divmod(minutes, 60)
    if hours:
        return "%dh%02dm" % (hours, minutes)
    return "%dm%02ds" % (minutes, sec)


def pid_alive(pid: int) -> bool:
    if pid <= 0:
        return False
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    except OSError:
        return False
    return True


def now() -> float:
    return time.time()
