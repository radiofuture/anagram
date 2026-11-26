"""The parts of the enclave processes that need no network: node config
(off by default), the node key, the node CLI, container set-up, the log
rules, the failover link, sealed state on disk, and the app's pack lines."""

from __future__ import annotations

import io
import json
import logging

import httpx
import pytest
from conftest import NODE_URL, make_net

from anagram.core.crypto.signing import SigningKey
from anagram.core.jsontable import JsonTable
from anagram.core.shared_db import SharedDB
from anagram.network.matching.app.enclave_matching import charter, pack_lines
from anagram.network.matching.hosting.enclave import DiskSnapshots, SealedFile
from anagram.network.matching.hosting.roster import RosterService, RosterStore
from anagram.network.matching.hosting.runtime import JsonFormatter, LogFieldRefused, event
from anagram.network.matching.hosting.tools.devnet import init_devnet
from anagram.network.matching.node.enclave_node import enclave_config
from anagram.network.matching.node.enclave_relay import FailoverLink
from anagram.shell.cli.main import main
from anagram.shell.node.setup import SetupError, enclave_from_env
from anagram.vectors.net.build_network import REC_A, REC_B
from anagram.vectors.net.fixtures import T0


@pytest.fixture
def pins(tmp_path) -> dict:
    return (
        init_devnet(tmp_path / "devnet", "net.anagram.test", "log.anagram.test/enclave")
        .pins()
        .to_json()
    )


def on(pins: dict, change: dict | None = None) -> dict:
    return {
        "enabled": True,
        "log_url": "http://log.test",
        "pins": pins,
        "record": {"admin": "admin@node.test", "affiliation": "Test Lab"},
        "urls": ["http://enclave-a.test"],
        **(change or {}),
    }


# ---- node config -------------------------------------------------------------


def test_a_node_without_enclave_config_is_unchanged(tmp_path) -> None:
    net = make_net(tmp_path)
    assert net.home.enclave_config()["enabled"] is False
    assert net.home.enclave() is None
    for method, path in (
        ("POST", "/net/credential"),
        ("GET", "/net/control"),
        ("GET", "/enclave/attestation"),
    ):
        assert net.tc.request(method, path).status_code in (404, 405), path


def test_the_node_has_a_network_key_and_an_older_home_gets_one(tmp_path) -> None:
    net = make_net(tmp_path)
    key_file = net.home.dir / "keys" / "network-ed25519.key"
    assert key_file.exists()  # made by `create`
    first = net.home.network_key().public_bytes()
    key_file.unlink()  # a home from before this key
    second = net.home.network_key().public_bytes()
    assert second != first and net.home.network_key().public_bytes() == second


@pytest.mark.parametrize(
    ("change", "words"),
    [
        ({"profile": "tee"}, "profile"),
        ({"urls": []}, "urls"),
        ({"urls": ["ftp://x"]}, "urls"),
        ({"log_url": "log"}, "log_url"),
        ({"pins": None}, "pins"),
        ({"tick_seconds": 0}, "tick_seconds"),
        ({"record": {"admin": "", "affiliation": "Lab"}}, "record"),
    ],
)
def test_an_incomplete_config_that_is_on_is_refused(pins, change, words) -> None:
    with pytest.raises(ValueError, match=words):
        enclave_config(on(pins, change))


def test_the_node_record_needs_an_https_public_url(tmp_path, pins) -> None:
    net = make_net(tmp_path)
    net.home.set_enclave(on(pins))
    rec = net.home.node_record()
    assert rec["url"] == NODE_URL and rec["id"].startswith("node-")
    assert rec["key"] == net.home.network_key().public_bytes().hex()


def test_node_enclave_cli_setup_record_status_off(tmp_path, pins, capsys) -> None:
    net = make_net(tmp_path)
    (tmp_path / "devnet.json").write_text(json.dumps(pins))
    base = ["node", "--node-dir", str(net.home.dir), "enclave"]
    assert main([*base, "status"]) == 0
    assert "off" in capsys.readouterr().out
    setup = ["--url", "http://127.0.0.1:9", "--log-url", "http://127.0.0.1:9"]
    setup += ["--pins", str(tmp_path / "devnet.json"), "--affiliation", "Lab", "--admin", "a@b.org"]
    assert main([*base, "setup", *setup]) == 0
    assert main([*base, "record"]) == 0
    assert json.loads(capsys.readouterr().out.split("\n", 2)[2])["affiliation"] == "Lab"
    assert main([*base, "status"]) == 1  # nothing answers at the URLs
    out = capsys.readouterr().out
    assert "log: not ok" in out and "enclave: unreachable" in out
    assert main([*base, "off"]) == 0
    assert net.home.enclave_config()["enabled"] is False


def test_container_set_up_reads_the_enclave_variables(tmp_path, pins) -> None:
    assert enclave_from_env({}) is None
    path = tmp_path / "devnet.json"
    path.write_text(json.dumps(pins))
    env = {
        "ANAGRAM_ENCLAVE_URLS": "http://a:1, http://b:1",
        "ANAGRAM_ENCLAVE_LOG_URL": "http://log:1",
        "ANAGRAM_ENCLAVE_PINS": str(path),
        "ANAGRAM_ENCLAVE_AFFILIATION": "Lab",
        "ANAGRAM_ENCLAVE_ADMIN": "a@b.org",
    }
    cfg = enclave_config(enclave_from_env(env))
    assert cfg["urls"] == ["http://a:1", "http://b:1"] and cfg["record"]["kind"] == "lab"
    assert cfg["tick_seconds"] == 60  # the default relay timer
    tick = enclave_config(enclave_from_env({**env, "ANAGRAM_ENCLAVE_TICK_SECONDS": "2"}))
    assert tick["tick_seconds"] == 2.0
    with pytest.raises(SetupError, match="PINS"):
        enclave_from_env({**env, "ANAGRAM_ENCLAVE_PINS": str(tmp_path / "missing.json")})


# ---- logs --------------------------------------------------------------------


def test_a_log_event_takes_only_safe_fields() -> None:
    logger = logging.getLogger("anagram.services.test")
    with pytest.raises(LogFieldRefused):
        event(logger, "upload", subject="ab" * 32)
    with pytest.raises(LogFieldRefused):
        event(logger, "upload", text="a line of a pack")


def test_the_formatter_keeps_no_library_values_and_no_exception_text() -> None:
    stream = io.StringIO()
    handler = logging.StreamHandler(stream)
    handler.setFormatter(JsonFormatter("test"))
    logger = logging.getLogger("anagram.services.formatter-test")
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)
    logger.propagate = False
    try:
        logger.warning("fetch %s failed", "secret-subject-key")
        try:
            raise RuntimeError("secret-line-text")
        except RuntimeError:
            logger.exception("failed")
        event(logger, "role", role="writer", instance_id="0" * 32)
    finally:
        logger.removeHandler(handler)
    lines = [json.loads(x) for x in stream.getvalue().splitlines()]
    assert "secret" not in stream.getvalue()
    assert lines[0]["event"] == "fetch %s failed"
    assert lines[1]["error"] == "RuntimeError"
    assert lines[2] == {**lines[2], "event": "role", "role": "writer", "service": "test"}


# ---- failover link -----------------------------------------------------------


def test_the_link_finds_the_writer_and_stays_with_it() -> None:
    seen: list = []
    a = httpx.Client(
        transport=httpx.MockTransport(lambda r: (seen.append("a"), httpx.Response(503))[1])
    )
    b = httpx.Client(
        transport=httpx.MockTransport(lambda r: (seen.append("b"), httpx.Response(200))[1])
    )
    link = FailoverLink([a, b])
    assert link.request("GET", "http://x/v1/attestation").status_code == 200
    assert link.request("GET", "http://x/v1/attestation").status_code == 200
    assert seen == ["a", "b", "b"]


def test_the_link_skips_a_stopped_instance_and_gives_503_when_none_writes() -> None:
    def refused(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("refused", request=request)

    down = httpx.Client(transport=httpx.MockTransport(refused))
    standby = httpx.Client(transport=httpx.MockTransport(lambda r: httpx.Response(503)))
    assert FailoverLink([down, standby]).request("GET", "http://x/").status_code == 503
    with pytest.raises(httpx.ConnectError):
        FailoverLink([down]).request("GET", "http://x/")
    with pytest.raises(ValueError):
        FailoverLink([])


# ---- sealed state on disk ----------------------------------------------------


def test_snapshots_and_the_sealed_record_survive_a_new_process(tmp_path) -> None:
    snaps = DiskSnapshots(tmp_path / "snapshots")
    snaps[3] = b"three"
    snaps[12] = b"twelve"
    del snaps[3]
    again = DiskSnapshots(tmp_path / "snapshots")
    assert list(again) == [12] and again[12] == b"twelve" and len(again) == 1
    with pytest.raises(KeyError):
        again[3]
    sealed = SealedFile(tmp_path)
    assert sealed.read() is None
    sealed.write({"role": "writer"})
    assert SealedFile(tmp_path).read() == {"role": "writer"}
    assert b"writer" not in (tmp_path / "instance.sealed").read_bytes()


def test_a_json_table_keeps_its_rows_across_connections(tmp_path) -> None:
    t = JsonTable(SharedDB(tmp_path / "t.sqlite"), "bindings")
    t["m1"] = "ab"
    t["m2"] = [1, {"x": 2}]
    t.setdefault("m1", "zz")
    del t["m2"]
    u = JsonTable(SharedDB(tmp_path / "t.sqlite"), "bindings")
    assert dict(u) == {"m1": "ab"} and len(u) == 1 and "m2" not in u


# ---- the app's lines -----------------------------------------------------------


def test_lens_lines_become_pack_lines() -> None:
    draft = {
        "offers": [
            {
                "class": "instrument",
                "match_types": ["T3", "T1"],
                "scope": "outside",
                "text": " A  B ",
            }
        ],
        "wants": [{"class": "data", "match_types": [], "scope": "both", "text": "Data"}],
    }
    lines = pack_lines(draft)
    assert lines["offers"] == [
        {
            "class": "instrument",
            "concepts": [],
            "id": "o01",
            "scope": "outside",
            "text": "A B",
            "types": ["instrument_access", "research_fit"],
        }
    ]
    assert lines["wants"][0]["id"] == "w01" and lines["wants"][0]["types"] == ["research_fit"]
    assert charter(lines, 3)["protocols"] == ["instrument_access", "research_fit"]
    assert charter(lines, 5)["weekly_cap"] == 5


class _Log:
    def append(self, entry: dict) -> int:
        return 0


def test_the_roster_removes_a_flooding_node(tmp_path) -> None:
    """C44 operator note (network.md 6.7): `anagram roster remove` writes
    `node_removed` with the reason `abuse`; a node that is not admitted, or
    removed already, is refused."""
    roster = RosterService(
        "net.anagram.test",
        SigningKey.generate(),
        RosterStore(tmp_path / "r.sqlite"),
        _Log(),
        lambda: T0,
    )
    roster.start()
    roster.admit(REC_A)
    ev = roster.remove(REC_A["id"], "abuse")
    assert ev["kind"] == "node_removed" and ev["body"] == {"node": REC_A["id"], "reason": "abuse"}
    for node, reason in ((REC_A["id"], "abuse"), (REC_B["id"], "abuse"), (REC_A["id"], "spam")):
        with pytest.raises(ValueError):
            roster.remove(node, reason)


@pytest.mark.parametrize(
    "draft",
    [
        {"offers": [], "wants": []},
        {"offers": [{"text": ""}]},
        {"offers": [{"text": "x", "class": "poem"}]},
        {"offers": [{"text": "x"}] * 6},
    ],
)
def test_bad_lines_are_refused(draft) -> None:
    from anagram.core.errors import ClientError

    with pytest.raises(ClientError):
        pack_lines(draft)
