"""A shuffle of the test order keeps the file order inside a story module
(`conftest.keep_story_order`): the module can move, and other tests move
freely."""

from __future__ import annotations

import random
from types import ModuleType, SimpleNamespace

from conftest import _COLLECTED, keep_story_order


def items(module: ModuleType, names: str, start: int) -> list[SimpleNamespace]:
    return [
        SimpleNamespace(module=module, name=n, stash={_COLLECTED: start + i})
        for i, n in enumerate(names)
    ]


def test_a_story_keeps_its_order_and_its_places_in_a_shuffle() -> None:
    story = ModuleType("test_walk")
    story.STORY = True  # type: ignore[attr-defined]
    other = ModuleType("test_other")
    for seed in range(20):
        got = items(story, "1234", 0) + items(other, "abcd", 4)
        random.Random(seed).shuffle(got)  # noqa: S311 (a test order, not a secret)
        places = [i for i, it in enumerate(got) if it.module is story]
        loose = [it.name for it in got if it.module is other]
        keep_story_order(got)  # type: ignore[arg-type]
        assert [it.name for it in got if it.module is story] == list("1234")
        assert [i for i, it in enumerate(got) if it.module is story] == places
        assert [it.name for it in got if it.module is other] == loose
