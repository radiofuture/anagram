"""The "What leaves this computer" entries of connected sources (plan R3
section 6, step S13)."""

from __future__ import annotations

from anagram.shell.ui.flows import FLOWS

BY_ID = {f["id"]: f for f in FLOWS}


def test_each_flow_has_the_five_keys_and_a_unique_id():
    assert len(BY_ID) == len(FLOWS)
    for f in FLOWS:
        assert set(f) == {"id", "to", "what", "when", "can_see"}, f["id"]
        assert all(isinstance(v, str) and v.strip() for v in f.values()), f["id"]


def test_connected_sources_name_the_services_and_what_they_see():
    f = BY_ID["connected-sources"]
    for service in ("Google", "Notion", "Zotero"):
        assert service in f["to"]
    assert "which items" in f["what"]
    assert "Not the community server" in f["can_see"]


def test_the_sign_in_stays_on_this_computer():
    f = BY_ID["source-sign-in"]
    assert f["to"] == "Nobody" and "keychain" in f["what"]


def test_source_flow_text_has_no_technical_word():
    text = " ".join(" ".join(BY_ID[i].values()) for i in ("connected-sources", "source-sign-in"))
    for word in ("token", "OAuth", "acct-", "keystore", "PKCE", "API"):
        assert word not in text, word
