"""The space model (`local/index/spaces.py`): the space of a source, the readable
spaces, and the scope check. No network."""

from __future__ import annotations

import pytest
from indexkit import KEY

from anagram.local.index import spaces
from anagram.local.index.local import LocalIndex
from anagram.local.sources import FolderConnector
from anagram.local.sources import source_state as ss

pytestmark = pytest.mark.usefixtures("no_network")

LAB_ID = "lab-0123456789abcdef"
LAB = "lab:" + LAB_ID


@pytest.fixture
def index(tmp_path):
    (tmp_path / "notes").mkdir()
    idx = LocalIndex(tmp_path / "index.sqlite", KEY)
    yield idx
    idx.close()


@pytest.fixture
def sid(index, tmp_path):
    return index.add_source(FolderConnector(tmp_path / "notes"))


def _state_rows(index) -> int:
    return index.store.one("SELECT count(*) FROM source_state")[0]


# -------------------------------------------------------------- constants


def test_constants_are_the_values_of_the_contract():
    assert spaces.PRIVATE == "private"
    assert spaces.PRIVATE is ss.PRIVATE
    assert spaces.PRIVATE_SCOPE == frozenset({"private"})
    assert isinstance(spaces.PRIVATE_SCOPE, frozenset)


def test_lab_space():
    assert spaces.lab_space(LAB_ID) == LAB
    assert ss.check_space(spaces.lab_space(LAB_ID)) == LAB


@pytest.mark.parametrize(
    "bad",
    ["", "a b", "lab", "lab-XYZ", "lab-0123456789ABCDEF", "lab:" + LAB_ID, LAB_ID + "0", None, 7],
)
def test_lab_space_refuses_a_bad_lab_id(bad):
    with pytest.raises(spaces.ScopeError):
        spaces.lab_space(bad)


# --------------------------------------------------------------- space_of


def test_source_with_no_state_row_is_private_and_no_row_is_made(index, sid):
    assert ss.read(index.store, sid) is None
    assert spaces.space_of(index, sid) == "private"
    assert _state_rows(index) == 0


def test_space_of_reads_the_column(index, sid):
    ss.get(index.store, sid)  # the row exists, default space
    assert spaces.space_of(index, sid) == "private"
    ss.set_space(index.store, sid, LAB, now=1.0)
    assert spaces.space_of(index, sid) == LAB
    ss.set_space(index.store, sid, "private", now=2.0)
    assert spaces.space_of(index, sid) == "private"


def test_space_of_agrees_with_sources_in_space(index, sid, tmp_path):
    other = index.add_source(FolderConnector(tmp_path))
    ss.set_space(index.store, sid, LAB, now=1.0)
    for space in ("private", LAB):
        members = ss.sources_in_space(index.store, space)
        assert members == [s for s in sorted([sid, other]) if spaces.space_of(index, s) == space]


def test_space_of_an_unknown_source_is_an_error(index):
    with pytest.raises(KeyError):
        spaces.space_of(index, "0" * 32)
    assert _state_rows(index) == 0


# -------------------------------------------------- readable_spaces, scope


class _NoLabCache:
    def readable_labs(self) -> list[str]:
        raise OSError("no lab cache")


@pytest.mark.parametrize("labs", [None, _NoLabCache()])
def test_readable_spaces_is_private_only_without_the_lab_unit(labs):
    assert spaces.readable_spaces(labs) == spaces.PRIVATE_SCOPE


def test_check_scope_accepts_a_readable_scope():
    assert spaces.check_scope(["private"], None) == spaces.PRIVATE_SCOPE
    assert spaces.check_scope(("private", "private"), None) == spaces.PRIVATE_SCOPE
    assert spaces.check_scope(spaces.PRIVATE_SCOPE, None) == spaces.PRIVATE_SCOPE
    assert spaces.check_scope(iter(["private"]), None) == spaces.PRIVATE_SCOPE
    assert spaces.check_scope("private", None) == spaces.PRIVATE_SCOPE  # one space as text
    assert isinstance(spaces.check_scope(["private"], None), frozenset)


def test_check_scope_refuses_a_space_that_is_not_readable():
    with pytest.raises(spaces.ScopeError, match="not readable"):
        spaces.check_scope([LAB], None)
    with pytest.raises(spaces.ScopeError, match="not readable"):
        spaces.check_scope(["private", LAB], None)


def test_check_scope_accepts_a_lab_that_is_readable(monkeypatch):
    """The check delegates to `readable_spaces` so space access changes in one place."""
    monkeypatch.setattr(spaces, "readable_spaces", lambda client: frozenset({"private", LAB}))
    assert spaces.check_scope([LAB], None) == frozenset({LAB})
    assert spaces.check_scope(["private", LAB], None) == frozenset({"private", LAB})
    with pytest.raises(spaces.ScopeError, match="not readable"):
        spaces.check_scope(["lab:lab-ffffffffffffffff"], None)


def test_refusal_does_not_name_the_space():
    with pytest.raises(spaces.ScopeError) as err:
        spaces.check_scope([LAB], None)
    assert LAB_ID not in str(err.value)


@pytest.mark.parametrize("bad", [[], (), "", ["all"], ["public"], ["lab:"], ["private", None], [7]])
def test_check_scope_refuses_an_empty_scope_and_a_value_that_is_not_a_space(bad):
    with pytest.raises(spaces.ScopeError):
        spaces.check_scope(bad, None)
