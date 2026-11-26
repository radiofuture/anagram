"""The app part of enclave matching: its HTTP clients and its clock."""

from __future__ import annotations

import logging
from types import SimpleNamespace

import httpx
import pytest

from anagram.core.devclock import OffsetClock, dev_clock_from_env
from anagram.network.matching.app.enclave_matching import EnclaveMatching
from anagram.network.matching.hosting.clients import HttpFeed
from anagram.network.matching.hosting.tools.devnet import init_devnet


class DictKV:
    def __init__(self) -> None:
        self.data: dict[str, str] = {}

    def kv_get(self, key: str) -> str | None:
        return self.data.get(key)

    def kv_set(self, key: str, value: str) -> None:
        self.data[key] = value

    def kv_delete(self, key: str) -> None:
        self.data.pop(key, None)

    def kv_items(self, prefix: str) -> list[tuple[str, str]]:
        return sorted((k, v) for k, v in self.data.items() if k.startswith(prefix))


def matching(connect=None, dev_clock=None) -> EnclaveMatching:
    device = SimpleNamespace(http=SimpleNamespace(base_url="https://node.example", token=None))
    extra = {"connect": connect} if connect is not None else {}
    return EnclaveMatching(device, DictKV(), lambda: 1_000, dev_clock=dev_clock, **extra)  # type: ignore[arg-type]


def test_the_app_reads_the_development_clock_only_for_development_pins(tmp_path) -> None:
    """M11: the offset clock of `ANAGRAM_DEV_CLOCK_FILE` moves the app's
    time only while the settings pin a development network (`dev_root`)."""
    em = matching(dev_clock=lambda: 9_000)
    assert em.now() == 1_000  # no network set up
    net = init_devnet(tmp_path / "devnet", "net.anagram.test", "log.anagram.test/enclave")
    em.set_settings("http://log.example", net.pins().to_json())
    assert em.now() == 9_000
    assert matching().now() == 1_000  # no variable: the device clock


def test_a_bad_development_clock_file_is_offset_zero(tmp_path, caplog) -> None:
    path = tmp_path / "offset"
    path.write_text("not a number\n")
    caplog.set_level(logging.WARNING, logger="anagram.core.devclock")
    assert OffsetClock(path, real=lambda: 500)() == 500
    assert "whole seconds" in caplog.text
    assert dev_clock_from_env({}) is None
    assert isinstance(dev_clock_from_env({"ANAGRAM_DEV_CLOCK_FILE": str(path)}), OffsetClock)


def test_the_app_keeps_one_client_for_each_url_and_closes_them() -> None:
    """M8: one HTTP client for each (URL, session) for the life of the
    object; `close` closes them."""
    made: list[httpx.Client] = []

    def connect(url: str, token: str | None) -> httpx.Client:
        made.append(httpx.Client(base_url=url))
        return made[-1]

    em = matching(connect=connect)
    first = em._node()  # noqa: SLF001 - the test counts the clients
    assert em._node() is first  # noqa: SLF001
    assert len(made) == 1
    em.close()
    assert first.is_closed


def test_the_control_feed_closes_its_clients() -> None:
    roster = httpx.Client()
    feed = HttpFeed(roster)
    node = httpx.Client()
    feed._nodes["node-a"] = node  # noqa: SLF001 - a client that a fetch made
    feed.close()
    assert roster.is_closed and node.is_closed


@pytest.mark.parametrize("value", ["", "  "])
def test_an_empty_development_clock_variable_is_no_clock(value: str) -> None:
    assert dev_clock_from_env({"ANAGRAM_DEV_CLOCK_FILE": value}) is None
