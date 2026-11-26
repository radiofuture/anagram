"""`anagram node start`: environment to node config, dev-mode guard, first organizer."""

from __future__ import annotations

import json

import pytest
from conftest import make_net

from anagram.admission.formats import parse_invite_url
from anagram.core.errors import Forbidden
from anagram.proofs.anchors.defaults import DEFAULT_ANCHORS
from anagram.shell.node.home import NodeHome
from anagram.shell.node.setup import (
    SetupError,
    check_dev_guard,
    check_existing,
    is_local_host,
    prepare,
    settings_from_env,
)

SECRET = "orcid-secret-value"  # noqa: S105 - test value
REAL = {
    "ANAGRAM_DOMAIN": "anagram.example.org",
    "ANAGRAM_COMMUNITY": "Example Biology",
    "ANAGRAM_ORCID_CLIENT_ID": "APP-123",
    "ANAGRAM_ORCID_CLIENT_SECRET": SECRET,
}
DEV = {
    "ANAGRAM_DOMAIN": "anagram.localhost",
    "ANAGRAM_PUBLIC_URL": "https://anagram.localhost:8443",
    "ANAGRAM_DEV_FAKE_ORCID": "1",
}


def test_real_env_to_config():
    s = settings_from_env(REAL)
    assert s.public_url == "https://anagram.example.org"
    assert s.origin == "anagram.example.org/log-v2"
    assert (s.orcid_mode, s.dev, s.community) == ("production", False, "Example Biology")
    assert s.anchors == list(DEFAULT_ANCHORS)
    assert not hasattr(s, "matching")  # C48: no matching settings on the node
    assert SECRET not in repr(s)
    sandbox = settings_from_env({**REAL, "ANAGRAM_ORCID_SANDBOX": "1"})
    assert sandbox.orcid_mode == "sandbox"
    custom = settings_from_env(
        {**REAL, "ANAGRAM_TSA_URLS": "https://a.test/tsr, http://b.test", "ANAGRAM_OTS": "off"},
    )
    assert custom.anchors == ["rfc3161:https://a.test/tsr", "rfc3161:http://b.test"]
    cal = settings_from_env({**REAL, "ANAGRAM_OTS_CALENDARS": "https://c.test"})
    assert cal.anchors[-1] == "opentimestamps:https://c.test"


def test_real_env_refusals():
    with pytest.raises(SetupError, match="ANAGRAM_DOMAIN"):
        settings_from_env({})
    with pytest.raises(SetupError, match="redirect URI to register"):
        settings_from_env({"ANAGRAM_DOMAIN": "a.example.org"})
    with pytest.raises(SetupError, match="fake anchor"):
        settings_from_env({**REAL, "ANAGRAM_ANCHORS": "fake,opentimestamps"})
    with pytest.raises(SetupError, match="https"):
        settings_from_env({**REAL, "ANAGRAM_PUBLIC_URL": "http://anagram.example.org"})
    with pytest.raises(SetupError, match="host"):
        settings_from_env({**REAL, "ANAGRAM_PUBLIC_URL": "https://other.example.org"})
    with pytest.raises(SetupError, match="whole number"):
        settings_from_env({**REAL, "ANAGRAM_ANCHOR_BATCH_SECONDS": "soon"})


def test_dev_mode_guard():
    assert is_local_host("localhost") and is_local_host("anagram.localhost")
    assert is_local_host("127.0.0.1") and not is_local_host("anagram.example.org")
    assert not is_local_host("localhost.example.org")
    check_dev_guard("https://anagram.localhost:8443", True)
    check_dev_guard("https://anagram.example.org", False)
    with pytest.raises(SetupError, match="refused"):
        check_dev_guard("https://anagram.example.org", True)
    with pytest.raises(SetupError, match="refused"):
        settings_from_env({**REAL, "ANAGRAM_DEV_FAKE_ORCID": "1"})
    s = settings_from_env(DEV)
    assert (s.orcid_mode, s.anchors, s.dev) == ("fake", ["fake"], True)


def test_first_start_prints_organizer_invite_once(tmp_path):
    nh = NodeHome(tmp_path / "node")
    lines: list[str] = []
    link = prepare(nh, DEV, out=lines.append)
    text = "\n".join(lines)
    assert link and link in text and "FIRST ORGANIZER INVITE" in text
    assert "DEV MODE" in text and "fake" in text
    cfg = nh.config()
    assert cfg["anchor_mode"] == "background" and cfg["public_url"] == DEV["ANAGRAM_PUBLIC_URL"]
    lines.clear()
    assert prepare(nh, {}, out=lines.append) is None  # second start: env not needed
    assert "FIRST ORGANIZER INVITE" not in "\n".join(lines)


def test_real_first_start(tmp_path):
    nh = NodeHome(tmp_path / "node")
    lines: list[str] = []
    assert prepare(nh, REAL, out=lines.append)
    text = "\n".join(lines)
    assert "DEV MODE" not in text and SECRET not in text
    assert "https://anagram.example.org/auth/orcid/callback" in text
    assert "fake" not in nh.config()["anchors"]
    assert SECRET not in nh.config_path.read_text()
    assert nh.orcid_client_secret() == SECRET


def test_existing_fake_node_on_real_domain_refused(tmp_path):
    nh = NodeHome(tmp_path / "node")
    prepare(nh, DEV, out=lambda _: None)
    raw = json.loads(nh.config_path.read_text())
    raw["public_url"] = "https://anagram.example.org"
    nh.config_path.write_text(json.dumps(raw))
    with pytest.raises(SetupError, match="refused"):
        check_existing(nh)


def test_organizer_invite(tmp_path):
    net = make_net(tmp_path)
    url = net.admission.create_invite(None, 7, organizer=True)["invite_url"]
    org = net.join(tmp_path / "org", "0000-0002-1825-0097", "Org", invite=url).client
    assert net.identity.community_stats()["organizers"] == 1
    # An organizer can make member invites, but not organizer invites.
    subject = org.config["identity"]["subject"]
    net.admission.create_invite(subject, 7)
    with pytest.raises(Forbidden):
        net.admission.create_invite(subject, 7, organizer=True)
    net.join(tmp_path / "m", "0000-0001-5109-3700", "Member")
    assert net.identity.community_stats() == {"members": 2, "organizers": 1}
    assert net.admission.open_invites() == 1
    # A member who claims an organizer invite becomes an organizer.
    doc = parse_invite_url(net.admission.create_invite(None, 7, organizer=True)["invite_url"])
    net.admission.claim_invite(net.sid("0000-0001-5109-3700"), doc["token"])
    assert net.identity.community_stats()["organizers"] == 2
