"""The log of the app: `<home>/logs/app.log` (2 MB, 3 old files).

The log is a plain file, so it must hold no name of a file or a folder, no
file content, and no secret. A person with a copy of the disk can read it.

Rules of the formatter:

- One line for each record: `time level logger message`.
- An exception is one short text: `ErrorClass at anagram/<module>.py:<line>`
  (the last frame in the `anagram` package). The exception message and the
  traceback are not written: a message can hold a path or text of a file.
- A log argument is written only if it is a number or one short word (an id,
  a class name, a task name). Each other argument becomes `<removed>`: a text
  with spaces can be an exception message with a file name in it.
- In the message, each absolute path (`/...`, `~/...`, `X:\\...`) and all text
  after it on that line becomes `<path>`. A path can have spaces, so the end
  of a path is not known. A URL keeps its address; its query and fragment
  become `?<removed>` (an open link holds a token in its path, so a path
  segment after `/open/` is removed too).

Code that logs must give ids and counts, not names. These rules are the
second barrier, not the first.

The full error text of the helper stays in the status record in the encrypted
index, where the UI shows it.
"""

from __future__ import annotations

import logging
import logging.handlers
import os
import re
from pathlib import Path

import anagram

LOG_DIR = "logs"
LOG_FILE = "app.log"
MAX_BYTES = 2_000_000
BACKUPS = 3
LOGGERS = ("anagram", "uvicorn")
PATH_MARK = "<path>"
QUERY_MARK = "?<removed>"

_PACKAGE = Path(anagram.__file__).resolve().parent

_URL = re.compile(r"(?P<base>[A-Za-z][A-Za-z0-9+.\-]*://[^\s'\"<>?#]*)(?P<rest>[?#][^\s'\"<>]*)?")
_OPEN = re.compile(r"(/open/)[^/\s'\"<>?#]+")
# A path start: `/x`, `~/x`, `~\x`, `C:\x`, `C:/x`. Not after a word character
# (so `new/changed` and `anagram/shell/ui/x.py` stay).
_PATH = re.compile(r"(?<![\w</\\])(?:~[/\\]|[A-Za-z]:[/\\]|/(?=[^\s/]))[^\n]*")
_KEEP = "\x00{}\x00"
_WORD = re.compile(r"[A-Za-z0-9_.:@+\-]{1,80}")
ARG_MARK = "<removed>"


def redact(text: str, known: tuple[str, ...] = ()) -> str:
    """Remove paths, URL queries, and open tokens from one log message.
    `known`: path prefixes that are removed where they occur in the text
    (the data directory and the home directory of the person)."""
    for prefix in known:
        if prefix and prefix in text:
            text = re.sub(re.escape(prefix) + r"[^\n]*", PATH_MARK, text)
    kept: list[str] = []

    def url(m: re.Match) -> str:
        base = _OPEN.sub(r"\1<removed>", m.group("base"))
        kept.append(base + (QUERY_MARK if m.group("rest") else ""))
        return _KEEP.format(len(kept) - 1)

    text = _URL.sub(url, text)
    text = _PATH.sub(PATH_MARK, text)
    for i, value in enumerate(kept):
        text = text.replace(_KEEP.format(i), value)
    return text


def plain_arg(value: object) -> object:
    """A log argument that is safe to write: a number, or one short word (an
    id, a class name, a task name, a time). Each other value becomes
    `<removed>`: a text with spaces can be an exception message."""
    if value is None or isinstance(value, bool | int | float):
        return value
    text = str(value)
    return text if _WORD.fullmatch(text) else ARG_MARK


def where(exc_info) -> str:
    """`ErrorClass at anagram/<module>.py:<line>`: the class of the exception
    and the last frame in this package. No exception message."""
    kind, _, tb = exc_info
    name = getattr(kind, "__name__", "Error")
    place = None
    while tb is not None:
        try:
            rel = Path(tb.tb_frame.f_code.co_filename).resolve().relative_to(_PACKAGE)
            place = f"anagram/{rel.as_posix()}:{tb.tb_lineno}"
        except (OSError, ValueError):
            pass
        tb = tb.tb_next
    return f"{name} at {place}" if place else name


class RedactingFormatter(logging.Formatter):
    def __init__(self, known: tuple[str, ...] = ()) -> None:
        super().__init__(datefmt="%Y-%m-%dT%H:%M:%S")
        # Longer prefixes first: the data directory is often in the home directory.
        self.known = tuple(sorted({k for k in known if len(k) > 1}, key=len, reverse=True))

    def format(self, record: logging.LogRecord) -> str:
        # `record.exc_text` is not used: another handler can have put the
        # full traceback there.
        args = record.args
        if isinstance(args, dict):
            args = {k: plain_arg(v) for k, v in args.items()}
        elif args:
            args = tuple(plain_arg(v) for v in args)
        try:
            message = str(record.msg) % args if args else str(record.msg)
        except Exception:  # a bad format string must not stop the log
            message = str(record.msg)
        message = redact(message, self.known).replace("\n", " | ")
        line = f"{self.formatTime(record, self.datefmt)} {record.levelname} {record.name} {message}"
        if record.exc_info and record.exc_info[0] is not None:
            line += f" [{where(record.exc_info)}]"
        return line


class _AppHandler(logging.handlers.RotatingFileHandler):
    """The handler of the app log (the class marks it for `teardown`)."""


def known_prefixes(home: Path) -> tuple[str, ...]:
    out = {str(home), str(Path.home())}
    for p in (home, Path.home()):
        try:
            out.add(str(p.resolve()))
        except OSError:
            pass
    return tuple(out)


def setup(home: str | Path) -> Path:
    """Send the `anagram` and `uvicorn` loggers to the app log of this data
    directory. A second call replaces the handler of the first call."""
    home = Path(home)
    teardown()
    directory = home / LOG_DIR
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    path = directory / LOG_FILE
    handler = _AppHandler(path, maxBytes=MAX_BYTES, backupCount=BACKUPS, encoding="utf-8")
    os.chmod(path, 0o600)
    handler.setFormatter(RedactingFormatter(known_prefixes(home)))
    for name in LOGGERS:
        logger = logging.getLogger(name)
        logger.addHandler(handler)
    logging.getLogger("anagram").setLevel(logging.INFO)
    return path


def teardown() -> None:
    """Remove the app log handler (the app stops; tests)."""
    for name in LOGGERS:
        logger = logging.getLogger(name)
        for handler in list(logger.handlers):
            if isinstance(handler, _AppHandler):
                logger.removeHandler(handler)
                handler.close()
