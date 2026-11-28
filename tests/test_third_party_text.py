"""Text that another person wrote stays context (spec/threat-model.md section
16). No network; fake Google, fake models.

The promise: a received mail (its subject, body, and attachments), a quoted
reply, and a Drive file of another owner are searchable only in the private
space as context. They are never own text, and never go into a brief, a
draft, a finding proposal, the lab space, an external model, or an MCP
answer."""

from __future__ import annotations

import json
from contextlib import contextmanager

import pytest
from indexkit import KEY
from sourcekit import creds_for, fake_client, google_account

from anagram.gateway import access
from anagram.gateway.server import HEADER, Server
from anagram.identity.app.keystore import MemoryKeystore
from anagram.local.api import lens_items
from anagram.local.index import retrieve
from anagram.local.index.convert.document import Document
from anagram.local.index.extract import extract_bytes, split_quoted
from anagram.local.index.local import LocalIndex
from anagram.local.index.spaces import PRIVATE_SCOPE
from anagram.local.sources import connector_from_config
from anagram.local.sources import source_state as ss
from anagram.local.sources.fake_google import FakeGoogle
from anagram.local.sources.gdrive import GoogleDriveConnector
from anagram.local.sources.gmail import GmailConnector
from anagram.local.sources.oauth import DRIVE_SCOPE, GMAIL_SCOPE
from anagram.local.trust.policy import TrustPolicy
from anagram.local.understanding import ask as ask_mod
from anagram.local.understanding import third_party
from anagram.local.understanding.drafter import FakeModelDrafter
from anagram.local.understanding.drafts import draft_findings_by_folder
from anagram.local.understanding.proposals import propose_findings
from anagram.models.providers.fake import FakeTextModel
from anagram.sim.writers import eml_bytes

pytestmark = pytest.mark.usefixtures("no_network")

OWN = "zymoquartz"  # only the member wrote this word
SUBJECT = "xylotrombe"  # the subject of a received mail
BODY = "quillionate"  # the body of a received mail
ATTACHED = "vorpalinth"  # an attachment of a received mail
DRIVE = "glimmerfax"  # a Drive file of another owner (name and text)
OUTLOOK = "brindlewort"  # an Outlook quote in an own reply
WRAPPED = "snickerbloom"  # a quote after a wrapped "On ... wrote:"
THEIRS = (SUBJECT, BODY, ATTACHED, DRIVE, OUTLOOK, WRAPPED)
ME = "mira@example.org"
NOW = "2026-11-16T10:00:00Z"


def _eml(sender: str, subject: str, body: str) -> bytes:
    return eml_bytes(
        sender=("X", sender),
        to=("Y", "y@example.org"),
        subject=subject,
        date="Mon, 02 Nov 2026 10:00:00 +0000",
        message_id="<m1@example.org>",
        body=body,
    )


# --------------------------------------------------------------- quote blocks


OUTLOOK_REPLY = f"""Yes, the {OWN} run is fine.

Mira

________________________________
From: Tomas Berg <tomas@example.org>
Sent: Monday, 2 November 2026 10:00
To: Mira <{ME}>
Subject: Gel

Can you check the {OUTLOOK} gel?
"""

OUTLOOK_NO_LINE = f"""Thanks.

From: Tomas Berg <tomas@example.org>
Sent: Monday, 2 November 2026 10:00
To: Mira
Subject: Gel

The {OUTLOOK} gel is ready.
"""

WRAPPED_REPLY = f"""I agree with the {OWN} plan.

On Mon, 2 Nov 2026 at 10:00, Tomas Berg <tomas@example.org>
wrote:

The {WRAPPED} result is odd.
"""


@pytest.mark.parametrize(
    ("body", "theirs"),
    [
        (OUTLOOK_REPLY, OUTLOOK),
        (OUTLOOK_NO_LINE, OUTLOOK),
        (WRAPPED_REPLY, WRAPPED),
        (f"Fine.\n\nBegin forwarded message:\n\nThe {WRAPPED} file.\n", WRAPPED),
        (f"See below, as Tomas wrote:\nThe {WRAPPED} file.\n", WRAPPED),
    ],
)
def test_quote_blocks_without_marks_are_quoted(body, theirs):
    own, quoted = split_quoted(body)
    assert theirs not in own and theirs in quoted
    assert "tomas@example.org" not in own


def test_text_after_a_quote_marker_stays_quoted():
    """Fail closed: after the first quote marker, no line is own again."""
    body = f"Mine.\n\n-----Original Message-----\nFrom: T\n\nTheirs.\n\n{WRAPPED} again.\n"
    own, quoted = split_quoted(body)
    assert own.strip() == "Mine." and WRAPPED in quoted


def test_an_own_reply_keeps_its_own_text():
    own, quoted = split_quoted(OUTLOOK_REPLY)
    assert OWN in own and OWN not in quoted


# ---------------------------------------------------- third-party and owner tests


def test_a_received_mail_has_no_own_text_no_title_and_no_subject():
    ex = extract_bytes(
        _eml("tomas@example.org", f"About {SUBJECT}", f"The {BODY}.\n"),
        "m.eml",
        "message/rfc822",
        frozenset({ME}),
    )
    assert ex.text == "" and ex.title is None
    assert SUBJECT in ex.quoted and BODY in ex.quoted
    assert SUBJECT not in json.dumps(ex.meta)


@pytest.mark.parametrize("owners", [frozenset(), frozenset({ME})])
def test_the_owner_test_fails_closed(owners):
    """No owner address, or no sender: the message is third-party."""
    for raw in (
        _eml("tomas@example.org", f"About {SUBJECT}", f"The {BODY}.\n"),
        f"Subject: About {SUBJECT}\r\n\r\nThe {BODY}.\r\n".encode(),  # no From
    ):
        ex = extract_bytes(raw, "m.eml", "message/rfc822", owners)
        assert ex.text == "" and ex.title is None and BODY in ex.quoted


def test_an_own_mail_keeps_its_text_and_quotes_a_reply_subject():
    raw = _eml(ME, f"Re: {SUBJECT}", f"The {OWN} plan.\n")
    ex = extract_bytes(raw, "m.eml", "message/rfc822", frozenset({ME}))
    assert OWN in ex.text and ex.title is None and SUBJECT in ex.quoted
    # The source hint: the Gmail label SENT says that the member wrote it.
    ex = extract_bytes(raw, "m.eml", "message/rfc822", frozenset(), own=True)
    assert OWN in ex.text and SUBJECT not in ex.text
    mine = extract_bytes(_eml(ME, "Plan", "Mine.\n"), "m.eml", "message/rfc822", frozenset({ME}))
    assert mine.title == "Plan" and mine.text.startswith("# Plan")


def test_as_context_moves_all_text():
    doc = Document(markdown="# T\n\nBody.", title="T", meta={"subject": "T", "date": "d"})
    out = third_party.as_context(doc)
    assert out.markdown == "" and out.title is None and out.blocks == []
    assert "Body." in out.quoted and out.meta == {"third_party": True, "date": "d"}


# ------------------------------------------------------------ connectors


class Clock:
    def __init__(self, now: float = 1_800_000_000.0) -> None:
        self.now = now

    def __call__(self) -> float:
        return self.now


class Env:
    def __init__(self, tmp_path):
        self.fake = FakeGoogle()
        self.clock = Clock()
        self.idx = LocalIndex(tmp_path / "index.sqlite", KEY, http=self.fake, clock=self.clock)
        self.creds = creds_for(
            MemoryKeystore(), self.idx.store, self.fake, self.clock, google=fake_client(self.fake)
        )
        self.idx.credentials = self.creds
        self.idx.owner_emails = frozenset({self.fake.email})
        self.acct = google_account(self.creds, self.fake, self.clock(), GMAIL_SCOPE, DRIVE_SCOPE)

    def add(self, **conf) -> str:
        sid = self.idx.add_source(connector_from_config({"account": self.acct.id, **conf}))
        self.idx.connectors.pop(sid)
        ss.ensure(self.idx.store, sid, self.clock(), account_id=self.acct.id)
        return sid

    def sync(self, sid: str) -> None:
        self.idx.connectors.pop(sid, None)
        self.idx.scan([sid], process=True)

    def rows(self, sid: str) -> dict[str, dict]:
        rows = self.idx.store.q(
            "SELECT i.key, i.name, d.markdown, d.title, d.quoted, d.meta FROM item i"
            " JOIN version v ON v.item_id = i.id JOIN document d ON d.version_id = v.id"
            " WHERE i.source_id = ?",
            (sid,),
        )
        return {r["key"]: dict(r) for r in rows}


@pytest.fixture
def env(tmp_path, monkeypatch):
    monkeypatch.setattr(GmailConnector, "rate", 1e9)
    monkeypatch.setattr(GoogleDriveConnector, "rate", 1e9)
    e = Env(tmp_path)
    yield e
    e.idx.close()


def _mailbox(m) -> dict:
    """A received mail with an attachment, and the member's reply with an
    Outlook quote and an attachment of the member."""
    q, t = m.add_message(
        f"The {SUBJECT} protocol",
        f"Can you send the {BODY} protocol?",
        sender="peer@uni.example",
        attachments=(("Notes " + ATTACHED + ".txt", "text/plain", f"{ATTACHED} data.".encode()),),
    )
    a, _ = m.add_message(
        "Protocol",
        OUTLOOK_REPLY,
        thread=t,
        sent=True,
        attachments=(("mine.txt", "text/plain", f"The {OWN} protocol.".encode()),),
    )
    return {"q": f"{t}/{q}", "a": f"{t}/{a}"}


def test_a_received_mail_and_its_attachment_are_context_only(env):
    keys = _mailbox(env.fake.gmail)
    sid = env.add(kind="gmail", filter={"mode": "all"})
    env.sync(sid)
    rows = env.rows(sid)
    got, att = rows[keys["q"]], rows[keys["q"] + "/a1"]
    for r in (got, att):
        blob = json.dumps({k: r[k] for k in ("name", "markdown", "title", "meta")})
        assert all(w not in blob.lower() for w in (SUBJECT, BODY, ATTACHED))
    assert got["name"].startswith("Received mail, ") and got["name"].endswith(".eml")
    assert att["name"].startswith("Attachment 1 of received mail, ")
    assert SUBJECT in got["quoted"] and BODY in got["quoted"] and ATTACHED in att["quoted"]
    own, own_att = rows[keys["a"]], rows[keys["a"] + "/a1"]
    assert OWN in own["markdown"] and OUTLOOK in own["quoted"] and OUTLOOK not in own["markdown"]
    assert OWN in own_att["markdown"] and own_att["name"] == "mine.txt"


def test_a_drive_file_of_another_owner_is_context_only(env):
    f = env.fake
    lab = f.add_folder("Lab")
    mine = f.add_file("plan.txt", f"The {OWN} plan.".encode(), parent=lab)
    theirs = f.add_file(
        f"{DRIVE} draft.txt", f"The {DRIVE} draft.".encode(), parent=lab, owner="peer@uni.example"
    )
    sid = env.add(kind="gdrive", include={"folders": [lab]})
    env.sync(sid)
    rows = env.rows(sid)
    assert OWN in rows[mine]["markdown"] and rows[mine]["name"] == "plan.txt"
    r = rows[theirs]
    assert DRIVE not in (r["name"] + r["markdown"] + (r["title"] or "")).lower()
    assert r["name"].startswith("Shared file, ") and DRIVE in r["quoted"]


def test_the_drive_owner_test_fails_closed(env):
    """With no known address of the member, a file with an owner is
    third-party."""
    f = env.fake
    lab = f.add_folder("Lab")
    fid = f.add_file("plan.txt", f"The {DRIVE} plan.".encode(), parent=lab)
    sid = env.add(kind="gdrive", include={"folders": [lab]})
    env.idx.connector(sid).api.email = None
    env.idx.scan([sid], process=True)
    r = env.rows(sid)[fid]
    assert r["markdown"] == "" and DRIVE in r["quoted"]


# ------------------------------------------------------------- end to end


@pytest.fixture
def world(env):
    """A fake mailbox (a received mail with an attachment, an own reply with
    an Outlook quote and a wrapped attribution) and a Drive folder with an
    own file and a file of another owner."""
    m = env.fake.gmail
    _mailbox(m)
    m.add_message("Plan", WRAPPED_REPLY, sent=True)
    lab = env.fake.add_folder("Lab")
    env.fake.add_file(
        "results.txt",
        f"We measured the {OWN} binding in three runs. The result held: the band"
        " moved by 12 kDa in each run. We need help with the statistics.".encode(),
        parent=lab,
    )
    env.fake.add_file(
        f"{DRIVE} draft.txt",
        f"We measured the {DRIVE} binding in four runs. The {DRIVE} result held:"
        f" the band moved by 9 kDa in each run. We need help with {DRIVE}.".encode(),
        parent=lab,
        owner="peer@uni.example",
    )
    mail = env.add(kind="gmail", filter={"mode": "all"})
    drive = env.add(kind="gdrive", include={"folders": [lab]})
    env.sync(mail)
    env.sync(drive)
    return env, mail, drive


def _clean(value) -> bool:
    blob = json.dumps(value, default=str).lower()
    return not [w for w in THEIRS if w in blob]


def test_text_of_other_people_never_leaves_the_private_context(world):
    env, mail, drive = world
    idx = env.idx
    # Searchable as context in the private space.
    for word in (SUBJECT, BODY, ATTACHED, DRIVE, OUTLOOK, WRAPPED):
        hits = retrieve.search(idx, word, scope=PRIVATE_SCOPE)
        assert hits and all(h.third_party for h in hits), word
        assert not retrieve.search(idx, word, scope=PRIVATE_SCOPE, context=False), word

    # Own items: no item of another person, no name or title with their text.
    own = idx.items(own_only=True)
    assert own and _clean([(i.name, i.ref) for i in own])
    assert len(idx.third_party_ids()) == 3  # the mail, its attachment, the Drive file
    for i in own:
        m = idx.meaning(i.source_id, i.key)
        assert m is None or _clean([m.extracted.title, m.extracted.text, m.extracted.meta])

    # The input of the matching lines draft (the profile lens): own items only.
    lens = lens_items(idx)
    assert lens and _clean([(i.id, i.text) for i in lens])

    # Finding proposals, with an external drafter that reads each proposal.
    others = idx.third_party_ids()
    their_keys = {
        (r["source_id"], r["key"])
        for r in idx.store.q("SELECT id, source_id, key FROM item")
        if r["id"] in others
    }
    for propose in (draft_findings_by_folder, propose_findings):
        ids = [d.id for d in propose(idx)]
        model = FakeModelDrafter()
        drafts = propose(idx, drafter=model, allow_external=True, select=ids)
        assert drafts and _clean(model.seen)
        for d in drafts:
            assert _clean([d.title, d.claim_suggestion, d.where, d.topics])
            assert _clean([(i.name, i.key) for i in d.items])
            assert not {(i.source_id, i.key) for i in d.items} & their_keys

    # Ask with a fake external model that has the opt-in on both sources.
    model = FakeTextModel(["ok [1]"], external=True, profile_id="cloud-12345678")
    idx.set_source_prefs(mail, allow_external=[model.recipient_id])
    idx.set_source_prefs(drive, allow_external=[model.recipient_id])
    for word in (*THEIRS, OWN):
        events = list(ask_mod.ask(idx, word, scope=PRIVATE_SCOPE, model=model))
        out = [e.data for e in events if e.type == "sources"]
        assert _clean([s for o in out for s in o["sources"] if not s["third_party"]])
    assert model.calls and _clean([(c.system, c.user) for c in model.calls])

    # An assistant (MCP): search, ask, read_item, and the timeline.
    @contextmanager
    def session():
        yield None, idx

    who = access.add(idx, "Claude Desktop", ["private"], NOW)
    server = Server(session, who.id, policy=lambda c, i: TrustPolicy.default("pid:" + "aa" * 16))

    def call(tool: str, **args):
        msg = {"id": 1, "jsonrpc": "2.0", "method": "tools/call"}
        msg["params"] = {"arguments": args, "name": tool}
        got = server.handle(msg)["result"]
        text = got["content"][0]["text"]
        if got["isError"]:
            return text
        head, _, body = text.partition("\n")
        assert head == HEADER
        return json.loads(body)

    seen = []
    for word in (*THEIRS, OWN):
        seen.append(call("search", query=word))
        got = call("ask", question=word)
        seen.append({k: v for k, v in got.items() if k != "question"})  # the echo
    assert any(h for s in seen if isinstance(s, dict) for h in s.get("hits", []))
    for iid in [r[0] for r in idx.store.q("SELECT id FROM item")]:
        seen.append(call("read_item", ref=f"item:{iid}"))
    seen.append(call("timeline", since="2020-01-01", until="2030-01-01"))
    assert _clean(seen)
    for iid in idx.third_party_ids():
        assert call("read_item", ref=f"item:{iid}") == "This item is not open to this assistant."


def test_the_lab_space_refuses_an_item_of_another_person(world):
    from anagram.network.groups.app import labspace
    from anagram.network.groups.app.labroster import LabError

    env, _, drive = world
    idx = env.idx
    src = idx.source(drive)
    rows = idx.store.q("SELECT id, key FROM item WHERE source_id = ?", (drive,))
    others = idx.third_party_ids()
    theirs = [r["key"] for r in rows if r["id"] in others]
    mine = [r["key"] for r in rows if r["id"] not in others]
    assert len(theirs) == 1 and len(mine) == 1
    with pytest.raises(LabError, match="Another person wrote this item"):
        labspace._draft(idx, src, drive, theirs[0])
    draft, _ = labspace._draft(idx, src, drive, mine[0])
    assert OWN in draft.text
