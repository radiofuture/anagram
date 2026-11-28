"""Copy lint of the local UI (plan R7 step 7b).

All visible text is in `ui/static/copy/*.json`, and screens and components
get it with `t('file.key')`. These checks keep the copy plain and the code
free of literal text:

- no tick or cross characters, no emoji, no "!", no banned phrases;
- a help text does not repeat its heading;
- no literal text between tags or in a text attribute of a screen or a
  component;
- each key that the code uses is in the copy, and each copy key is used
  (a template key such as t(`account.drafting_${id}`) uses its prefix);
- no HTML sink (innerHTML and the like) in the code of the UI.

A known exception goes in `tests/fixtures/copy_allowlist.json`, and the test
checks the count, so a new exception is a change that a reviewer sees.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

STATIC = Path(__file__).resolve().parents[1] / "src/anagram/shell/ui/static"
COPY = STATIC / "copy"
JS = STATIC / "js"
ALLOW = json.loads(
    (Path(__file__).parent / "fixtures/copy_allowlist.json").read_text(encoding="utf-8")
)

BANNED_CHARS = re.compile("[✓✔✕✖✗✘✅❌❎!\U0001f300-\U0001faff☀-⛿]")
BANNED_PHRASES = (
    "success",
    "oops",
    "please note",
    "simply",
    "seamless",
    "powerful",
    "magic",
    "tick the",
    "click here",
    "awesome",
    "great!",
    "congratulations",
    "ai-powered",
)


def _flatten(prefix: str, value) -> dict[str, str]:
    """Each text of a copy file: key -> text. A plural object is one key."""
    if isinstance(value, str):
        return {prefix: value}
    if set(value) <= {"one", "other"}:
        return {f"{prefix}.{form}": text for form, text in value.items()} | {prefix: value["other"]}
    out: dict[str, str] = {}
    for k, v in value.items():
        out |= _flatten(f"{prefix}.{k}", v)
    return out


def copy_texts() -> dict[str, str]:
    out: dict[str, str] = {}
    for f in sorted(COPY.glob("*.json")):
        out |= _flatten(f.stem, json.loads(f.read_text(encoding="utf-8")))
    return out


def copy_keys() -> set[str]:
    """The keys that `t()` can name (a plural object is one key)."""
    out: set[str] = set()

    def walk(prefix: str, value) -> None:
        if isinstance(value, str) or set(value) <= {"one", "other"}:
            out.add(prefix)
            return
        for k, v in value.items():
            walk(f"{prefix}.{k}", v)

    for f in sorted(COPY.glob("*.json")):
        walk(f.stem, json.loads(f.read_text(encoding="utf-8")))
    return out


def code_files() -> list[Path]:
    return sorted(JS.rglob("*.js"))


def screen_files() -> list[Path]:
    return sorted(
        [
            *(JS / "screens").glob("*.js"),
            *(JS / "components").glob("*.js"),
            *(JS / "parts").glob("*.js"),
            *(JS / "slots").glob("*.js"),
        ]
    )


def test_copy_has_no_banned_character_or_phrase():
    bad = []
    for key, text in copy_texts().items():
        if key in ALLOW["banned"]:
            continue
        if BANNED_CHARS.search(text):
            bad.append((key, text))
        low = text.lower()
        bad += [(key, phrase) for phrase in BANNED_PHRASES if phrase in low]
    assert not bad, bad


def test_help_does_not_repeat_its_heading():
    texts = copy_texts()
    bad = []
    for key, title in texts.items():
        stem = re.sub(r"(^|_)title$", "", key.rsplit(".", 1)[1])
        if not key.endswith("title") or not title:
            continue
        ns = key.rsplit(".", 1)[0]
        for suffix in ("help", "lead", "text"):
            other = texts.get(f"{ns}.{stem}_{suffix}" if stem else f"{ns}.{suffix}")
            if other and other.lower().startswith(title.lower()):
                bad.append((key, other))
    assert not bad, bad


# Text between tags: ">Some words<". A tag with only an expression or with
# punctuation (",", "·") is not text.
LITERAL_TEXT = re.compile(r">\s*([A-Za-z][A-Za-z ,.'’-]{1,}[A-Za-z.])\s*<")
LITERAL_ATTR = re.compile(
    r"\b(aria-label|placeholder|title|alt|label|summary)=\"([^\"$]*[A-Za-z]{2}[^\"$]*)\""
)


def test_screens_and_components_have_no_literal_text():
    bad = []
    for f in screen_files():
        src = f.read_text(encoding="utf-8")
        for block in re.findall(r"html`(.*?)`;", src, re.DOTALL):
            bad += [(f.name, m) for m in LITERAL_TEXT.findall(block)]
            bad += [(f.name, f"{a}={v}") for a, v in LITERAL_ATTR.findall(block)]
    bad = [b for b in bad if f"{b[0]}: {b[1]}" not in ALLOW["literal"]]
    assert not bad, bad


KEY = re.compile(r"""['"]([a-z]+(?:\.[a-z0-9_]+)+)['"]""")
PREFIX = re.compile(r"`([a-z]+\.[a-z0-9_.]*)\$\{")


SUFFIX = re.compile(r"\$\{[^}`]+\}(\.[a-z0-9_]+)`")


def used_keys() -> tuple[set[str], set[str], set[str]]:
    """Keys in quotes, prefixes of t(`ns.key_${x}`), and suffixes of t(`${id}.nav`)."""
    stems = {f.stem for f in COPY.glob("*.json")}
    keys: set[str] = set()
    prefixes: set[str] = set()
    suffixes: set[str] = set()
    for f in code_files():
        src = f.read_text(encoding="utf-8")
        keys |= {k for k in KEY.findall(src) if k.split(".")[0] in stems}
        prefixes |= {p for p in PREFIX.findall(src) if p.split(".")[0] in stems}
        suffixes |= set(SUFFIX.findall(src))
    return keys, prefixes, suffixes


def test_each_used_key_is_in_the_copy():
    keys, _, _ = used_keys()
    known = copy_keys()
    # A string like 'common.picker' names a group of keys (a component reads its parts).
    groups = {k.rsplit(".", 1)[0] for k in known}
    missing = sorted(
        k for k in keys if k not in known and k not in groups and k not in ALLOW["not_keys"]
    )
    assert not missing, missing


def test_each_copy_key_is_used():
    keys, prefixes, suffixes = used_keys()
    unused = sorted(
        k
        for k in copy_keys()
        if k not in keys
        and not any(k.startswith(p) for p in prefixes)
        and not any(k.endswith(x) for x in suffixes)
        and not any(k.startswith(g + ".") for g in keys)
    )
    assert unused == sorted(ALLOW["unused"]), unused


@pytest.mark.parametrize(
    "sink",
    ["innerHTML", "outerHTML", "insertAdjacentHTML", "dangerouslySetInnerHTML", "document.write"],
)
def test_no_html_sink(sink):
    bad = [f.name for f in code_files() if sink in f.read_text(encoding="utf-8")]
    assert not bad, (sink, bad)


def test_the_checks_find_what_they_look_for():
    assert LITERAL_TEXT.findall("<p>Save the kit</p>") == ["Save the kit"]
    assert LITERAL_TEXT.findall("<p>${t('a.b')}</p>") == []
    assert LITERAL_ATTR.findall('<a aria-label="Close it">') == [("aria-label", "Close it")]
    assert LITERAL_ATTR.findall('<a aria-label=${t("a.b")}>') == []
    assert BANNED_CHARS.search("Saved ✓") and BANNED_CHARS.search("Done!")
    assert KEY.findall("t(ok ? 'account.turn_on' : 'account.turn_off')") == [
        "account.turn_on",
        "account.turn_off",
    ]
    assert PREFIX.findall("t(`account.drafting_${m.id}`)") == ["account.drafting_"]
    assert SUFFIX.findall("t(`${s.id}.nav`)") == [".nav"]


def test_allowlist_count_is_known():
    """A new exception changes this count: a reviewer sees it."""
    assert sum(len(v) for v in ALLOW.values()) == ALLOW_COUNT


ALLOW_COUNT = 5
