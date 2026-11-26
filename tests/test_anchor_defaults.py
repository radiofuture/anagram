"""Default anchors: bundled TSA roots, recorded live tokens, verify output.

The records in fixtures/live were made once by hand on 2026-10-15 against the
real FreeTSA and DigiCert TSAs and the public OpenTimestamps calendars. The
tests only read them (no network).
"""

import json
from pathlib import Path

from anagram.proofs.anchors import AnchorTrust, verify_anchor
from anagram.proofs.anchors.defaults import (
    DEFAULT_ANCHORS,
    anchor_kind,
    bundled_tsa_roots,
    describe_record,
)
from anagram.proofs.proof import VerifyReport

LIVE = json.loads((Path(__file__).parent / "fixtures/live/anchors-2026-10-15.json").read_text())
DIGEST = bytes.fromhex(LIVE["digest"])


def test_defaults_are_real_anchors():
    kinds = [anchor_kind(s) for s in DEFAULT_ANCHORS]
    assert "fake" not in kinds
    assert kinds.count("rfc3161") >= 2 and "opentimestamps" in kinds


def test_recorded_tsa_tokens_verify_with_bundled_roots():
    trust = AnchorTrust(tsa_roots=bundled_tsa_roots())
    sources = set()
    for url in ("https://freetsa.org/tsr", "http://timestamp.digicert.com"):
        check = verify_anchor(LIVE["records"][url], DIGEST, trust)
        assert check.ok, (url, check.detail)
        assert check.time.year == 2026
        sources.add(check.source)
    assert len(sources) == 2  # two distinct TSAs count as two sources
    # Without pinned roots the same tokens are not counted.
    assert not verify_anchor(LIVE["records"]["https://freetsa.org/tsr"], DIGEST, AnchorTrust()).ok
    # A different digest fails.
    assert not verify_anchor(LIVE["records"]["https://freetsa.org/tsr"], b"\0" * 32, trust).ok


def test_recorded_ots_record_is_pending():
    check = verify_anchor(LIVE["records"]["ots"], DIGEST, AnchorTrust())
    assert not check.ok and check.pending


def test_describe_and_report_lines():
    assert "freetsa.org" in describe_record(LIVE["records"]["https://freetsa.org/tsr"])
    assert "NO independent time" in describe_record({"type": "fake"})
    r = VerifyReport()
    assert "none" in r.anchor_lines()[0]
    r.anchor_notes = [(describe_record({"type": "fake"}), "valid, x")]
    assert any("WARNING" in line for line in r.anchor_lines())
