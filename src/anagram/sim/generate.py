"""Generate the synthetic community on disk.

Layout of OUT_DIR:

    ground_truth.json   people, labs, institutions, planted matches, blocks, files
    canaries.json       every canary string and the file that holds it
    labs/<lab>/<person>/notes|figures|decks|mail|data|code|library|raw/...

The same seed gives the same bytes. Git metadata other than commit IDs (for
example the index file) is not part of that promise.
"""

from __future__ import annotations

import csv
import hashlib
import hmac
import io
import json
import random
from dataclasses import dataclass, field
from pathlib import Path

from anagram.sim import writers
from anagram.sim.labs import (
    BLOCKS,
    INSTITUTIONS,
    LABS,
    LABS_BY_SLUG,
    PLANTED_MATCHES,
    Lab,
    Mail,
    Person,
    pair,
)

GROUND_TRUTH_SCHEMA = "anagram.sim.ground_truth.v1"
CANARIES_SCHEMA = "anagram.sim.canaries.v1"
DEFAULT_LARGE_BYTES = 20 * 1024 * 1024
CSV_ROWS = 24


@dataclass
class SimResult:
    out_dir: Path
    ground_truth: dict
    canaries: list[dict]


def _h(seed: int, *parts: str) -> str:
    return hashlib.sha256("|".join([str(seed), *parts]).encode()).hexdigest()


def fake_orcid(seed: int, person: Person) -> str:
    d = str(int(_h(seed, "orcid", person.slug), 16) % 10**9).zfill(9)
    return f"fake-0000-000{d[0]}-{d[1:5]}-{d[5:9]}"


def fake_ror(seed: int, key: str) -> str:
    return f"fake-ror-{_h(seed, 'ror', key)[:9]}"


def _chip(kind: str, label: str) -> dict:
    slug = label.lower().replace(" ", "-")
    return {"label": label, "id": f"tbd:{kind}/{slug}"}


@dataclass
class _Book:
    """Allocates canaries and records files."""

    seed: int
    out_dir: Path
    canaries: list[dict] = field(default_factory=list)
    files: list[dict] = field(default_factory=list)
    counters: dict[str, int] = field(default_factory=dict)

    def canary(
        self,
        lab: Lab,
        orcid: str,
        path: str,
        kind: str,
        *,
        member: str | None = None,
        third_party: bool = False,
    ) -> str:
        n = self.counters.get(lab.slug, 0) + 1
        self.counters[lab.slug] = n
        key = f"anagram-sim:{self.seed}".encode()
        mac = hmac.new(key, f"{lab.slug}|{n}|{path}|{member}".encode(), "sha256").hexdigest()
        value = f"CANARY-{lab.slug.upper()}-{n:03d}-{mac[:12]}"
        self.canaries.append(
            {
                "canary": value,
                "lab_id": lab.id,
                "person_orcid": orcid,
                "path": path,
                "member": member,
                "kind": kind,
                "third_party": third_party,
            }
        )
        return value

    def rel(self, path: Path) -> str:
        return path.relative_to(self.out_dir).as_posix()

    def write(
        self, path: Path, data: bytes, *, lab: Lab, orcid: str, kind: str, media_type: str
    ) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        self.record(path, lab, orcid, kind, media_type, len(data), hashlib.sha256(data).hexdigest())

    def record(
        self,
        path: Path,
        lab: Lab,
        orcid: str,
        kind: str,
        media_type: str,
        size: int | None,
        sha256: str | None,
        **extra: object,
    ) -> None:
        self.files.append(
            {
                "path": self.rel(path),
                "lab_id": lab.id,
                "person_orcid": orcid,
                "kind": kind,
                "media_type": media_type,
                "size": size,
                "sha256": sha256,
                **extra,
            }
        )


def _rng(seed: int, *parts: str) -> random.Random:
    return random.Random("|".join([str(seed), *parts]))  # noqa: S311 - test data


def _dataset_rows(lab: Lab, rng: random.Random) -> list[list[str]]:
    rows = []
    for i in range(CSV_ROWS):
        if lab.slug == "chen":
            res = rng.uniform(2.4, 4.5)
            row = [f"G{10 + i // 3}-{i % 3 + 1}", rng.choice(["LMNG", "DDM", "GDN"]),
                   f"{rng.uniform(1.5, 4.5):.1f}", str(rng.randint(25, 80)),
                   str(rng.randint(20_000, 400_000)), f"{res:.2f}"]  # fmt: skip
        elif lab.slug == "okafor":
            fam = rng.choice(["kinase", "protease", "transporter", "channel", "nuclear receptor"])
            true = rng.uniform(4.0, 10.0)
            err = rng.uniform(0.1, 2.8 if fam in ("transporter", "channel") else 1.4)
            pred = true + rng.choice([-1, 1]) * err
            row = [f"CPX-{40000 + i * 7}", fam, str(rng.randint(1800, 9000)),
                   f"{pred:.2f}", f"{true:.2f}", f"{err:.2f}"]  # fmt: skip
        elif lab.slug == "varga":
            day = (0, 1, 3, 5, 7, 14)[i % 6]
            row = [f"LK-M{i // 6 + 1:02d}", "3", str(day), f"{min(60, 5 + day * 3.5 + rng.uniform(-4, 4)):.1f}",
                   f"{rng.uniform(9.5, 11.5):.2f}", f"{rng.uniform(0.4, 2.2):.2f}"]  # fmt: skip
        else:
            inh = rng.uniform(0, 95)
            row = [f"HX-{4400 + i}", "0412", f"{'ABCDEFGHIJKLMNOP'[i % 16]}{i % 24 + 1:02d}",
                   f"{inh:.1f}", f"{(inh - 20) / 9:.2f}", "HX-4410" if inh > 50 else "other"]  # fmt: skip
        rows.append(row)
    return rows


def _mail_text(mail: Mail, own_canary: str, quoted_canary: str) -> str:
    quoted = "".join(f"> {line}\n" for line in mail.quoted.splitlines())
    return (
        f"{mail.body}\nInternal ref: {own_canary}\n\n"
        f"On {mail.date}, {mail.quoted_from[0]} <{mail.quoted_from[1]}> wrote:\n"
        f"{quoted}> Ref: {quoted_canary}\n"
    )


def _write_mail(book: _Book, lab: Lab, orcid: str, path: Path, mail: Mail) -> None:
    rel = book.rel(path)
    own = book.canary(lab, orcid, rel, "eml")
    third = book.canary(lab, orcid, rel, "eml", third_party=True)
    domain = mail.sender[1].split("@")[1]
    msg_id = f"<{_h(book.seed, 'msgid', rel)[:20]}@{domain}>"
    data = writers.eml_bytes(
        sender=mail.sender,
        to=mail.to,
        subject=mail.subject,
        date=mail.date,
        message_id=msg_id,
        body=_mail_text(mail, own, third),
    )
    book.write(path, data, lab=lab, orcid=orcid, kind="email", media_type="message/rfc822")


def _write_text(book: _Book, lab: Lab, orcid: str, path: Path, text: str, media_type: str) -> None:
    canary = book.canary(lab, orcid, book.rel(path), "note")
    data = f"{text}\nInternal ref: {canary}\n".encode()
    book.write(path, data, lab=lab, orcid=orcid, kind="note", media_type=media_type)


def _pi_evidence(book: _Book, lab: Lab, person: Person, orcid: str, base: Path) -> None:
    stem, body = lab.plan
    _write_text(book, lab, orcid, base / "notes" / f"{stem}.md", body, "text/markdown")

    path = base / "decks" / f"{lab.slug}-talk.pptx"
    title, slides = lab.deck
    last = len(slides)
    member = f"ppt/slides/slide{last}.xml"
    canary = book.canary(lab, orcid, book.rel(path), "pptx", member=member)
    slide_list = [(head, list(bullets)) for head, bullets in slides]
    slide_list[-1][1].append(f"Internal ref: {canary}")
    data = writers.pptx_bytes(
        title, person.name, slide_list, notes_comment="Fictional deck, Anagram synthetic community"
    )
    book.write(
        path,
        data,
        lab=lab,
        orcid=orcid,
        kind="slides",
        media_type="application/vnd.openxmlformats-officedocument.presentationml.presentation",
    )

    _write_mail(book, lab, orcid, base / "mail" / "collaborator-thread.eml", lab.pi_mail)

    path = base / "library" / "zotero-export.json"
    canary = book.canary(lab, orcid, book.rel(path), "zotero")
    items = []
    for i, (title, authors, year, venue) in enumerate(lab.library, start=1):
        item = {
            "id": f"{lab.slug}-item-{i}",
            "type": "article-journal",
            "title": title,
            "author": [{"family": a.split(", ")[0], "given": a.split(", ")[1]} for a in authors],
            "issued": {"date-parts": [[year]]},
            "container-title": venue,
            "DOI": f"10.5555/fake.{lab.slug}.{i}",
            "note": "Fictional reference for the Anagram synthetic community.",
        }
        if i == 1:
            item["note"] += f" Private reading note. Internal ref: {canary}"
        items.append(item)
    data = (json.dumps(items, indent=2, sort_keys=True) + "\n").encode()
    book.write(
        path,
        data,
        lab=lab,
        orcid=orcid,
        kind="zotero",
        media_type="application/vnd.citationstyles.csl+json",
    )


def _scientist_evidence(
    book: _Book, lab: Lab, person: Person, orcid: str, base: Path, large_bytes: int
) -> None:
    stem, body = lab.notebook
    _write_text(book, lab, orcid, base / "notes" / f"{stem}.md", body, "text/markdown")

    stem, caption, style = lab.figure
    path = base / "figures" / f"{stem}.png"
    canary = book.canary(lab, orcid, book.rel(path), "png")
    w, h = 96, 64
    pixels = writers.figure_pixels(_rng(book.seed, "png", lab.slug), w, h, style)
    data = writers.png_bytes(w, h, pixels, {"Title": caption, "Comment": f"Internal ref: {canary}"})
    book.write(path, data, lab=lab, orcid=orcid, kind="image", media_type="image/png")

    stem, columns = lab.dataset
    path = base / "data" / f"{stem}.csv"
    canary = book.canary(lab, orcid, book.rel(path), "csv")
    rows = _dataset_rows(lab, _rng(book.seed, "csv", lab.slug))
    buf = io.StringIO()
    out = csv.writer(buf, lineterminator="\n")
    out.writerow(columns)
    for i, row in enumerate(rows):
        out.writerow([*row, f"Internal ref: {canary}" if i == 0 else ""])
    book.write(
        path, buf.getvalue().encode(), lab=lab, orcid=orcid, kind="dataset", media_type="text/csv"
    )

    name, commits = lab.repo
    repo = base / "code" / name
    git_canary = book.canary(lab, orcid, book.rel(repo / "README.md"), "git")
    plan = []
    for i, (message, files) in enumerate(commits):
        texts = dict(files)
        if i == 0:
            texts["README.md"] += f"\nInternal ref: {git_canary}\n"
        plan.append((message, texts, f"2026-09-{1 + i * 7:02d}T10:00:00+00:00"))
    head = writers.make_git_repo(repo, (person.name, person.email), plan)
    book.record(
        repo, lab, orcid, "git", "inode/directory", None, None, head=head, commits=len(plan)
    )

    fname, header_text = lab.large
    path = base / "raw" / fname
    canary = book.canary(lab, orcid, book.rel(path), "large")
    header = f"# {header_text}\n# Internal ref: {canary}\n".encode()
    path.parent.mkdir(parents=True, exist_ok=True)
    digest = writers.write_large_file(path, large_bytes, f"{book.seed}|large|{lab.slug}", header)
    book.record(
        path, lab, orcid, "large", "application/octet-stream", max(large_bytes, len(header)), digest
    )


def _manager_evidence(book: _Book, lab: Lab, person: Person, orcid: str, base: Path) -> None:
    stem, body = lab.manager_note
    _write_text(book, lab, orcid, base / "notes" / f"{stem}.txt", body, "text/plain")
    _write_mail(book, lab, orcid, base / "mail" / "vendor-thread.eml", lab.vendor_mail)


def _match_reason(a: Lab, b: Lab) -> dict:
    return {
        f"{a.slug}_gets": sorted(set(a.need_chips) & set(b.offer_chips)),
        f"{b.slug}_gets": sorted(set(b.need_chips) & set(a.offer_chips)),
    }


def build_ground_truth(seed: int, book: _Book | None = None) -> dict:
    """Return the ground-truth manifest (without files when `book` is None)."""
    institutions = [
        {"id": fake_ror(seed, inst.key), "key": inst.key, "name": inst.name, "kind": inst.kind}
        for inst in INSTITUTIONS.values()
    ]
    people, labs = [], []
    for lab in LABS:
        orcids = []
        for person in lab.people:
            orcid = fake_orcid(seed, person)
            orcids.append(orcid)
            people.append(
                {
                    "orcid": orcid,
                    "name": person.name,
                    "role": person.role,
                    "title": person.title,
                    "email": person.email,
                    "lab_id": lab.id,
                    "path": f"labs/{lab.slug}/{person.slug}",
                }
            )
        labs.append(
            {
                "id": lab.id,
                "slug": lab.slug,
                "name": lab.name,
                "institution_id": fake_ror(seed, lab.institution),
                "field": lab.field,
                "has": lab.has,
                "needs": lab.needs,
                "people": orcids,
                "path": f"labs/{lab.slug}",
                "profile": {
                    "topics": [_chip("topic", t) for t in lab.topics],
                    "needs": [_chip("need", t) for t in lab.need_chips],
                    "offers": [_chip("offer", t) for t in lab.offer_chips],
                },
            }
        )
    blocked = {pair(blocker, target) for blocker, kind, target, _ in BLOCKS if kind == "lab"}
    planted = [
        {
            "labs": [LABS_BY_SLUG[a].id, LABS_BY_SLUG[b].id],
            "reason": _match_reason(LABS_BY_SLUG[a], LABS_BY_SLUG[b]),
        }
        for a, b in PLANTED_MATCHES
    ]
    expected = [
        p["labs"]
        for p, (a, b) in zip(planted, PLANTED_MATCHES, strict=True)
        if pair(a, b) not in blocked
    ]
    suppressed = [
        p["labs"]
        for p, (a, b) in zip(planted, PLANTED_MATCHES, strict=True)
        if pair(a, b) in blocked
    ]
    return {
        "schema": GROUND_TRUTH_SCHEMA,
        "seed": seed,
        "fictional": True,
        "institutions": institutions,
        "labs": labs,
        "people": people,
        "planted_matches": planted,
        "blocks": [
            {
                "blocker": LABS_BY_SLUG[blocker].id,
                "target_kind": kind,
                "target": LABS_BY_SLUG[target].id,
                "reason": reason,
            }
            for blocker, kind, target, reason in BLOCKS
        ],
        "expected_matches": expected,
        "suppressed_matches": suppressed,
        "files": book.files if book else [],
    }


def _dump(path: Path, obj: object) -> None:
    path.write_bytes((json.dumps(obj, indent=2, sort_keys=True) + "\n").encode())


def generate_community(
    out_dir: str | Path, seed: int = 0, large_bytes: int = DEFAULT_LARGE_BYTES
) -> SimResult:
    """Write the synthetic community to `out_dir` and return the manifests.

    `out_dir` must not exist or must be empty.
    """
    out = Path(out_dir)
    if out.exists() and any(out.iterdir()):
        raise FileExistsError(f"{out} is not empty")
    if large_bytes < 0:
        raise ValueError("large_bytes must not be negative")
    out.mkdir(parents=True, exist_ok=True)
    book = _Book(seed=seed, out_dir=out)
    for lab in LABS:
        roles = {p.role for p in lab.people}
        for person in lab.people:
            orcid = fake_orcid(seed, person)
            base = out / "labs" / lab.slug / person.slug
            if person.role == "pi":
                _pi_evidence(book, lab, person, orcid, base)
            elif person.role == "scientist":
                _scientist_evidence(book, lab, person, orcid, base, large_bytes)
                if "manager" not in roles:
                    _manager_evidence(book, lab, person, orcid, base)
            else:
                _manager_evidence(book, lab, person, orcid, base)
    truth = build_ground_truth(seed, book)
    canaries = {"schema": CANARIES_SCHEMA, "seed": seed, "canaries": book.canaries}
    _dump(out / "ground_truth.json", truth)
    _dump(out / "canaries.json", canaries)
    return SimResult(out_dir=out, ground_truth=truth, canaries=book.canaries)
