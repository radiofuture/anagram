"""The space model: where an item is readable.

A space is `private` or `lab:<lab id>`. An item has the space of its source.
The one field is the column `source_state.space` (`source_state.py` stores it
and checks its form). A source with no `source_state` row is in the private
space. An item has no space field.

A scope is a set of spaces in one retrieval call. Retrieval code gets its
scope from `check_scope` or `readable_spaces` and filters on
`source_state.space` in SQL. It does not make a scope from request text
without `check_scope`.

`readable_spaces` returns the private space and each lab whose current key
this device holds.
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import TYPE_CHECKING

from anagram.core.errors import FormatError
from anagram.identity.api import validate_lab_id
from anagram.local.sources import source_state

if TYPE_CHECKING:
    from anagram.local.index.local import LocalIndex
    from anagram.local.ports import LabContext

PRIVATE = source_state.PRIVATE
PRIVATE_SCOPE: frozenset[str] = frozenset({PRIVATE})

_LAB_PREFIX = "lab:"


class ScopeError(Exception):
    """A scope is empty, has a value that is not a space, or has a space that
    this device cannot read. The message names no space."""


def lab_space(lab_id: str) -> str:
    """The space of a lab: `lab:<lab_id>`. The lab ID must have the form of
    `formats.identity.validate_lab_id` (`lab-<16 hex>`)."""
    try:
        return source_state.check_space(_LAB_PREFIX + validate_lab_id(lab_id))
    except (FormatError, source_state.SourceStateError):
        raise ScopeError("this is not a lab ID") from None


def space_of(idx: LocalIndex, sid: str) -> str:
    """The space of a source and of its items. It reads `source_state.space`
    and makes no row. A source with no state row is private. An unknown
    source raises `KeyError`, as `LocalIndex.source` does."""
    state = source_state.read(idx.store, sid)
    if state is not None:
        return state.space
    if idx.store.one("SELECT 1 FROM source WHERE id = ?", (sid,)) is None:
        raise KeyError(f"no source {sid}")
    return PRIVATE


def readable_spaces(labs: LabContext | None) -> frozenset[str]:
    """The spaces that this device can read: the private space, and each lab
    whose key this device holds. `labs` is the lab context of the person
    (`Client.lab_context`), or None when there is no session.

    A lab is in the result only if the lab context says that it can read it
    now (`readable_labs`): the person is in the verified roster, has not
    left, and holds the key of the current epoch. Old keys alone are not
    enough (a removed member keeps them). No lab context, or a fault in the
    local lab cache, gives `PRIVATE_SCOPE`."""
    if labs is None:
        return PRIVATE_SCOPE
    try:
        ids = labs.readable_labs()
    except Exception:  # no session or no cache: the private space only
        return PRIVATE_SCOPE
    out = set(PRIVATE_SCOPE)
    for lab_id in ids:
        try:
            out.add(lab_space(lab_id))
        except ScopeError:
            continue
    return frozenset(out)


def check_scope(asked: Iterable[str], labs: LabContext | None) -> frozenset[str]:
    """Make a scope from the spaces that a caller asked for. Each space must
    have the correct form and must be in `readable_spaces(labs)`. An empty
    scope is refused: a call with no space is a caller fault, not a search
    with no result."""
    values = [asked] if isinstance(asked, str) else list(asked)
    if not values:
        raise ScopeError("a scope has one space or more")
    for value in values:
        try:
            source_state.check_space(value)
        except source_state.SourceStateError:
            raise ScopeError("a space is 'private' or 'lab:<lab id>'") from None
    scope = frozenset(values)
    if not scope <= readable_spaces(labs):
        # The same message for a lab that does not exist and for a lab that
        # this person is not in.
        raise ScopeError("a space of this scope is not readable on this device")
    return scope
