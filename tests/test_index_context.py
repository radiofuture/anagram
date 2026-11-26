"""Chunks of class `context` (R4 step 12a, integration 1.9): text that other
people wrote in mail.

A word that only another person wrote is found with the scope `private`, with
`third_party: true`. It is not found with a lab scope, and it is in no
proposal, no `understand` prompt, and no brief context. (The MCP server is
step 16; its test checks the same rule.) No network."""

from __future__ import annotations

import pytest
from indexkit import KEY

from anagram.local.api import lens_items
from anagram.local.index import retention, retrieve
from anagram.local.index.chunk import context_chunks
from anagram.local.index.convert.document import Document
from anagram.local.index.local import LocalIndex
from anagram.local.index.spaces import PRIVATE_SCOPE
from anagram.local.sources import FolderConnector
from anagram.local.sources import source_state as ss
from anagram.local.understanding import understand
from anagram.local.understanding.proposals import propose_findings
from anagram.models.providers.fake import FakeTextModel
from anagram.sim.writers import eml_bytes

pytestmark = pytest.mark.usefixtures("no_network")

ME = "mira@example.org"
OTHER = "tomas@example.org"
LAB = "lab:lab-0123456789abcdef"
THEIRS = "quillionate"  # only the other person wrote this word
QUOTED = "brindlefox"  # only in quoted text of my reply


def _mail(folder, name: str, sender: str, body: str) -> None:
    folder.mkdir(parents=True, exist_ok=True)
    data = eml_bytes(
        sender=("Someone", sender),
        to=("Other", ME if sender != ME else OTHER),
        subject="Gel results",
        date="Mon, 02 Nov 2026 10:00:00 +0000",
        message_id=f"<{name}@example.org>",
        body=body,
    )
    (folder / name).write_bytes(data)


@pytest.fixture
def mail(tmp_path):
    inbox, shared = tmp_path / "inbox", tmp_path / "shared"
    _mail(
        inbox,
        "received.eml",
        OTHER,
        f"We found that the {THEIRS} buffer moves the band by 12 kDa in three runs.\n",
    )
    _mail(
        inbox,
        "reply.eml",
        ME,
        "Thanks, I will run the gel again on Monday with the old buffer and the new one.\n"
        "I want to see if the band moves in the same way, and I will keep the control lane.\n"
        "After that I write the notes for the group meeting and send the figures to you.\n\n"
        f"On Mon, Tomas wrote:\n> The {QUOTED} sample is ready in the cold room.\n",
    )
    (inbox / "finding.md").write_text(
        "# Band shift\n\nWe found that the new buffer moves the band by 12 kDa in three runs.\n"
        "The control lane did not move. This is the main claim of the gel work this month.\n"
        "We ran each gel at the same voltage, and the ladder stayed in the same place in each run.\n"
        "Next we test the buffer with a second protein to see if the shift is general.\n",
        encoding="utf-8",
    )
    _mail(shared, "lab-received.eml", OTHER, f"The {THEIRS} stock for the lab is low.\n")
    idx = LocalIndex(tmp_path / "index.sqlite", KEY, owner_emails=[ME])
    a = idx.add_source(FolderConnector(inbox))
    b = idx.add_source(FolderConnector(shared))
    idx.scan()
    ss.set_space(idx.store, b, LAB, now=1.0)
    yield idx, a, b
    idx.close()


def test_context_chunks_are_kept_apart():
    doc = Document(markdown="# Mine\n\nMy text.", quoted="Their text.\n\nMore of their text.")
    got = context_chunks(doc)
    assert [c.text for c in got] == ["Their text.", "More of their text."]
    assert all(c.anchor.startswith("quoted/") for c in got)
    assert context_chunks(Document(markdown="x")) == []


def test_a_word_of_another_person_is_found_in_the_private_space_only(mail):
    idx, _, _ = mail
    hits = retrieve.search(idx, THEIRS, scope=PRIVATE_SCOPE)
    assert len(hits) == 1 and hits[0].third_party and hits[0].space == "private"
    assert hits[0].json()["third_party"] is True
    quoted = retrieve.search(idx, QUOTED, scope=PRIVATE_SCOPE)
    assert len(quoted) == 1 and quoted[0].third_party and quoted[0].anchor.startswith("quoted/")
    # The lab copy of the word is in a lab-space source: never found, with any scope.
    assert retrieve.search(idx, THEIRS, scope=frozenset({LAB})) == []
    assert len(retrieve.search(idx, THEIRS, scope=frozenset({"private", LAB}))) == 1
    # A caller that must not read other people's text.
    assert retrieve.search(idx, THEIRS, scope=PRIVATE_SCOPE, context=False) == []


def test_the_own_chunks_do_not_hold_the_text_of_other_people(mail):
    idx, _, _ = mail
    rows = [r[0] for r in idx.store.q("SELECT text FROM chunk")]
    assert rows and not any(THEIRS in t or QUOTED in t for t in rows)
    assert idx.search(THEIRS) == [] and idx.search(QUOTED) == []


def test_no_understand_prompt_proposal_or_lens_item_gets_the_text(mail):
    idx, _, _ = mail
    model = FakeTextModel()
    understand.run(idx, model, limit=50)
    assert model.calls, "the fake model read the own items"
    assert not any(THEIRS in c.user or QUOTED in c.user for c in model.calls)
    for d in propose_findings(idx):
        text = repr((d.title, d.claim_suggestion, d.reason, [i.name for i in d.items]))
        assert THEIRS not in text and QUOTED not in text
    lens = lens_items(idx)  # the input of the matching lines draft
    assert THEIRS not in repr(lens) and QUOTED not in repr(lens)


def test_a_new_version_and_a_removed_source_drop_the_context_chunks(mail, tmp_path):
    idx, a, _ = mail
    _mail(tmp_path / "inbox", "received.eml", OTHER, "We found nothing new this week.\n")
    idx.scan()
    assert retrieve.search(idx, THEIRS, scope=PRIVATE_SCOPE) == []
    assert len(retrieve.search(idx, QUOTED, scope=PRIVATE_SCOPE)) == 1
    retention.remove_source(idx, a, delete_data=True)
    assert retrieve.search(idx, QUOTED, scope=PRIVATE_SCOPE) == []
    left = idx.store.q(
        "SELECT c.text FROM context_chunk c JOIN version v ON v.id = c.version_id"
        " WHERE v.source_id = ?",
        (a,),
    )
    assert left == []
