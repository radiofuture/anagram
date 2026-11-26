"""Preprint draft: one zip with a manuscript draft and the priority proofs.

The draft is a start for a preprint server, not a submission: Anagram sends
nothing to a server. No model call. The input is one finding and its
`includes` tree (depth 3, no cycles). Each finding of the tree is one
section; its image evidence goes to `figures/`, its other evidence to
`supplement/` (if `include_files`). A file that is not on this computer is
named in `MISSING.txt`.

| Path in the zip | Content |
|---|---|
| `manuscript.md`, `manuscript.tex`, `manuscript.html` | The same text in three forms |
| `figures/fig-<n>-<name>` | Image evidence |
| `supplement/<name>` | Other evidence |
| `proof/certificate-<root12>.html`, `proof/<root12>.proof.json` | One pair for each finding |
| `proof/VERIFY.txt` | How to check with no network |
| `metadata.json`, `CITATION.cff` | Title, authors, findings, time |

The "Priority record" text states no more than the certificate.
"""

from __future__ import annotations

import html
import json
import re
import zipfile
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING

from anagram.core.errors import ClientError
from anagram.proofs.certificate import certificate_bundle, make_certificate, owner_of, verify_url
from anagram.proofs.records import LINK_INCLUDES

if TYPE_CHECKING:
    from anagram.proofs.ports import FindingSource

MAX_DEPTH = 3
_SAFE = re.compile(r"[^A-Za-z0-9._-]+")


@dataclass
class _Finding:
    root: str
    finding_id: str
    version: int
    claim: str
    not_after: datetime
    figures: list[tuple[str, Path]] = field(default_factory=list)  # (zip path, file)
    files: list[tuple[str, Path | None]] = field(default_factory=list)  # (name, file or None)
    depth: int = 0

    @property
    def title(self) -> str:
        first = self.claim.strip().splitlines()[0].strip() if self.claim.strip() else ""
        return first or f"Finding {self.root[:12]}"

    @property
    def body(self) -> str:
        lines = self.claim.strip().splitlines()
        return "\n".join(lines[1:]).strip()


def _safe(name: str) -> str:
    stem = _SAFE.sub("-", Path(name).name).strip("-.")
    return stem or "file"


def _when(t: datetime) -> str:
    t = t.astimezone(UTC)
    return f"{t.day} {t:%B %Y}, {t:%H:%M:%S} UTC"


def _tree(client: FindingSource, ref: str) -> tuple[list[tuple[str, int]], list[str]]:
    """The roots of the tree in reading order with their depth, and the
    roots that are linked but not in this vault."""
    order: list[tuple[str, int]] = []
    missing: list[str] = []
    seen: set[str] = set()

    def walk(root: str, depth: int) -> None:
        if root in seen or depth > MAX_DEPTH:
            return
        seen.add(root)
        order.append((root, depth))
        fields = client.findings.opening(root).finding.fields
        for i in range(int(fields.get("link_count") or 0)):
            link = fields.get(f"links.{i}") or {}
            if link.get("type") != LINK_INCLUDES:
                continue
            target = link.get("target")
            if client.vault.get(target) is None:
                missing.append(target)
                continue
            walk(target, depth + 1)

    walk(client.vault.find(ref).root, 0)
    return order, missing


# ----------------------------------------------------------------- text


def _authors(authors: list[dict]) -> str:
    parts = []
    for a in authors:
        bits = [a.get("name") or "Author"]
        if a.get("orcid"):
            bits.append(f"ORCID {a['orcid']}")
        if a.get("affiliation"):
            bits.append(a["affiliation"])
        parts.append(", ".join(bits))
    return "; ".join(parts)


def _record_line(f: _Finding, url: str | None) -> str:
    where = url or "see proof/VERIFY.txt"
    return (
        f"A cryptographic record of this work existed no later than {_when(f.not_after)}."
        f" Digest: {f.root}. Verify: {where}."
    )


def _sections(items: list[_Finding]) -> list[_Finding]:
    """The findings that get a section. The parent of a set gives the title
    and the abstract; it gets its own section only if it has files."""
    parent = items[0]
    if len(items) > 1 and not parent.figures and not parent.files:
        return items[1:]
    return items


def _markdown(title, authors, abstract, items: list[_Finding], url, missing) -> str:
    out = [
        f"# {title}",
        "",
        f"**Authors:** {_authors(authors)}",
        "",
        "## Abstract",
        "",
        abstract,
        "",
    ]
    n_fig = 0
    for i, f in enumerate(_sections(items), 1):
        out += [f"## {i}. {f.title}", ""]
        if f.body and f.body != abstract:
            out += [f.body, ""]
        for path, _ in f.figures:
            n_fig += 1
            out += [f"![Figure {n_fig}]({path})", "", f"*Figure {n_fig}.* {Path(path).name}", ""]
        if f.files:
            out += ["Files:", ""] + [f"- {name}" for name, _ in f.files] + [""]
    out += ["## Priority record", ""]
    out += [f"- {f.title}: {_record_line(f, url)}" for f in items]
    if missing:
        out += ["", "Some linked findings are not on this computer. See MISSING.txt."]
    return "\n".join(out) + "\n"


_TEX_ESC = {
    "\\": r"\textbackslash{}",
    "&": r"\&",
    "%": r"\%",
    "$": r"\$",
    "#": r"\#",
    "_": r"\_",
    "{": r"\{",
    "}": r"\}",
    "~": r"\textasciitilde{}",
    "^": r"\textasciicircum{}",
}


def tex_escape(text: str) -> str:
    return "".join(_TEX_ESC.get(ch, ch) for ch in text)


def _tex(title, authors, abstract, items: list[_Finding], url, missing) -> str:
    e = tex_escape
    names = r" \and ".join(
        e(a.get("name") or "Author")
        + (r"\\ ORCID " + e(a["orcid"]) if a.get("orcid") else "")
        + (r"\\ " + e(a["affiliation"]) if a.get("affiliation") else "")
        for a in authors
    )
    out = [
        r"\documentclass[11pt]{article}",
        r"\usepackage[utf8]{inputenc}",
        r"\usepackage[T1]{fontenc}",
        r"\usepackage{graphicx}",
        r"\usepackage{url}",
        r"\title{" + e(title) + "}",
        r"\author{" + names + "}",
        r"\date{}",
        r"\begin{document}",
        r"\maketitle",
        r"\begin{abstract}",
        e(abstract),
        r"\end{abstract}",
    ]
    for f in _sections(items):
        out.append(r"\section{" + e(f.title) + "}")
        if f.body and f.body != abstract:
            out.append(e(f.body))
        for path, _ in f.figures:
            out += [
                r"\begin{figure}[h]",
                r"\centering",
                r"\includegraphics[width=0.8\linewidth]{" + path + "}",
                r"\caption{" + e(Path(path).name) + "}",
                r"\end{figure}",
            ]
        if f.files:
            out.append(r"\begin{itemize}")
            out += [r"\item " + e(name) for name, _ in f.files]
            out.append(r"\end{itemize}")
    out.append(r"\section*{Priority record}")
    out.append(r"\begin{itemize}")
    for f in items:
        where = r"\url{" + url + "}" if url else "see proof/VERIFY.txt"
        out.append(
            r"\item "
            + e(f.title)
            + ": A cryptographic record of this work existed no later than "
            + e(_when(f.not_after))
            + r". Digest: \texttt{"
            + f.root
            + "}. Verify: "
            + where
            + "."
        )
    out.append(r"\end{itemize}")
    if missing:
        out.append("Some linked findings are not on this computer. See MISSING.txt.")
    out.append(r"\end{document}")
    return "\n".join(out) + "\n"


_HTML_CSS = """
body{margin:0;background:#f5f3ee;color:#24202c;font:17px/1.6 Georgia,'Times New Roman',serif}
main{max-width:690px;margin:0 auto;padding:56px 24px 72px}
h1,h2{font-family:Arial,sans-serif;font-weight:400;letter-spacing:-.02em;line-height:1.15}
h1{font-size:2rem;margin:0 0 12px}h2{font-size:1.25rem;margin:40px 0 8px}
.authors{color:#625c69;font-family:Arial,sans-serif;font-size:.95rem}
figure{margin:24px 0}figure img{max-width:100%}figcaption{font-size:.9rem;color:#625c69}
code{font-size:.8rem;overflow-wrap:anywhere}
.record{border-top:1px solid #24202c;margin-top:48px;padding-top:8px;font-size:.95rem}
@media print{body{background:#fff}main{padding:0}}
"""


def _html(title, authors, abstract, items: list[_Finding], url, missing) -> str:
    e = html.escape
    out = [
        '<!doctype html><html lang="en"><head><meta charset="utf-8">',
        '<meta name="viewport" content="width=device-width, initial-scale=1">',
        f"<title>{e(title)}</title><style>{_HTML_CSS}</style></head><body><main>",
        f"<h1>{e(title)}</h1>",
        f'<p class="authors">{e(_authors(authors))}</p>',
        "<h2>Abstract</h2>",
        f"<p>{e(abstract)}</p>",
    ]
    n_fig = 0
    for i, f in enumerate(_sections(items), 1):
        out.append(f"<h2>{i}. {e(f.title)}</h2>")
        if f.body and f.body != abstract:
            out += [f"<p>{e(p)}</p>" for p in f.body.split("\n\n")]
        for path, _ in f.figures:
            n_fig += 1
            out.append(
                f'<figure><img src="{e(path)}" alt="Figure {n_fig}">'
                f"<figcaption>Figure {n_fig}. {e(Path(path).name)}</figcaption></figure>"
            )
        if f.files:
            out.append("<ul>" + "".join(f"<li>{e(n)}</li>" for n, _ in f.files) + "</ul>")
    out.append('<section class="record"><h2>Priority record</h2><ul>')
    for f in items:
        out.append(f"<li>{e(f.title)}: {e(_record_line(f, url))}</li>")
    out.append("</ul>")
    if missing:
        out.append("<p>Some linked findings are not on this computer. See MISSING.txt.</p>")
    out.append("</section></main></body></html>\n")
    return "".join(out)


def _verify_txt(items: list[_Finding], url: str | None) -> str:
    lines = [
        "How to check the priority proofs of this draft",
        "",
        "Each finding has two files in this folder: a certificate (.html) and a",
        "proof file (.proof.json). They hold the same proof.",
        "",
        "With no network, with the Anagram command:",
        "",
    ]
    for f in items:
        lines.append(
            f"  anagram verify proof/{f.root[:12]}.proof.json --file <a file of the finding>"
        )
    lines.append("")
    if url:
        lines += [f"On the web: open {url} and drop a certificate or a proof file on the page.", ""]
    lines += [
        "A proof shows that the signing key signed the record, and that the",
        "public log had it no later than the time on the certificate. It does not",
        "show who made the work or what the files mean.",
    ]
    return "\n".join(lines) + "\n"


def _cff(title: str, authors: list[dict], when: datetime) -> str:
    def q(s: str) -> str:
        return json.dumps(s, ensure_ascii=False)

    out = [
        "cff-version: 1.2.0",
        "message: If you use this work, cite it as below.",
        f"title: {q(title)}",
        "authors:",
    ]
    for a in authors:
        name = (a.get("name") or "Author").strip()
        given, _, family = name.rpartition(" ")  # "Ada Lovelace": given "Ada"
        out.append(f"  - family-names: {q(family)}")
        if given:
            out.append(f"    given-names: {q(given)}")
        if a.get("orcid"):
            out.append(f"    orcid: {q('https://orcid.org/' + a['orcid'])}")
        if a.get("affiliation"):
            out.append(f"    affiliation: {q(a['affiliation'])}")
    out.append(f"date-released: {when.astimezone(UTC):%Y-%m-%d}")
    return "\n".join(out) + "\n"


# ---------------------------------------------------------------- build


def build_preprint(
    client: FindingSource,
    ref: str,
    out: str | Path,
    *,
    include_files: bool = True,
    authors: list[dict] | None = None,
    abstract: str | None = None,
    now: datetime | None = None,
) -> Path:
    """Write the preprint draft zip of one finding and its `includes` tree to
    `out`. Raises ClientError if a proof of the tree is not complete."""
    now = now or datetime.now(UTC)
    out = Path(out)
    order, missing_links = _tree(client, ref)
    url = verify_url(client)
    if authors is None:
        owner = owner_of(client) or {}
        authors = [
            {
                "affiliation": None,
                "name": owner.get("name") or "Author",
                "orcid": owner.get("orcid"),
                "ror": None,
            }
        ]
    items: list[_Finding] = []
    proofs: dict[str, str] = {}
    missing_files: list[str] = []
    n_fig = 0
    for root, depth in order:
        name, cert, report = make_certificate(client, root, now=now)
        if not report.ok or report.not_after is None:
            raise ClientError(
                f"the proof of finding {root[:12]} is not complete yet; try again later"
            )
        proofs[f"proof/{name.replace('anagram-certificate-', 'certificate-')}"] = cert
        proofs[f"proof/{root[:12]}.proof.json"] = certificate_bundle(client, root).dumps()
        row = client.vault.get(root)
        doc = client.findings.opening(root)
        meta = client.vault.evidence_meta(root)
        f = _Finding(
            root=root,
            finding_id=row.finding_id,
            version=row.version,
            claim=doc.finding.fields.get("claim") or "",
            not_after=report.not_after,
            depth=depth,
        )
        n_fig = _add_evidence(f, doc.evidence, meta, missing_files, n_fig)
        items.append(f)

    parent = items[0]
    title = parent.title
    abstract = (abstract or "").strip() or parent.body or parent.title
    metadata = {
        "abstract": abstract,
        "authors": authors,
        "findings": [
            {
                "finding_id": f.finding_id,
                "not_after": f.not_after.astimezone(UTC).isoformat(),
                "root": f.root,
                "version": f.version,
            }
            for f in items
        ],
        "generated_at": now.astimezone(UTC).isoformat(),
        "target_hints": {
            "arxiv": "Upload manuscript.tex and the figures folder. Check the text first.",
            "biorxiv": "Open manuscript.html, print it to PDF, and upload the PDF.",
        },
        "title": title,
    }
    args = (title, authors, abstract, items, url, missing_links)
    out.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(out, "w", compression=zipfile.ZIP_DEFLATED) as z:
        z.writestr("manuscript.md", _markdown(*args))
        z.writestr("manuscript.tex", _tex(*args))
        z.writestr("manuscript.html", _html(*args))
        z.writestr("metadata.json", json.dumps(metadata, indent=2, ensure_ascii=False) + "\n")
        z.writestr("CITATION.cff", _cff(title, authors, now))
        z.writestr("proof/VERIFY.txt", _verify_txt(items, url))
        for path, text in proofs.items():
            z.writestr(path, text)
        used: set[str] = set()
        written: set[Path] = set()  # a file in two findings goes in one time
        for f in items:
            for path, src in f.figures:
                z.write(src, path)
            if include_files:
                _write_supplement(z, f.files, used, written)
        missing = [f"Linked finding not on this computer: {r}" for r in missing_links]
        missing += [f"File not on this computer: {m}" for m in missing_files]
        if missing:
            z.writestr("MISSING.txt", "\n".join(missing) + "\n")
    return out


def _add_evidence(
    f: _Finding, evidence: list, meta: dict, missing_files: list[str], n_fig: int
) -> int:
    """Add the evidence files of a finding to `f`: an image on this computer
    is a figure, another file is a supplement file. A file that is not on
    this computer goes into `missing_files`. Return the new figure count."""
    for slot, ev in enumerate(evidence):
        ev_name = ev.fields.get("name") or f"file-{slot + 1}"
        path = (meta.get(slot) or {}).get("path")
        here = Path(path) if path and Path(path).is_file() else None
        if here is None:
            missing_files.append(f"{f.title}: {ev_name}")
        if str(ev.fields.get("media_type", "")).startswith("image/") and here is not None:
            n_fig += 1
            f.figures.append((f"figures/fig-{n_fig}-{_safe(ev_name)}", here))
        else:
            f.files.append((ev_name, here))
    return n_fig


def _write_supplement(
    z: zipfile.ZipFile,
    files: list[tuple[str, Path | None]],
    used: set[str],
    written: set[Path],
) -> None:
    """Write the supplement files of one finding. A file in `written` is not
    written again; a name in `used` gets a number."""
    for name, src in files:
        if src is None or src.resolve() in written:
            continue
        written.add(src.resolve())
        arc = f"supplement/{_safe(name)}"
        k = 2
        while arc in used:
            arc = f"supplement/{k}-{_safe(name)}"
            k += 1
        used.add(arc)
        z.write(src, arc)


def preprint_name(root: str) -> str:
    return f"anagram-preprint-{root[:12]}.zip"


__all__ = ["build_preprint", "preprint_name", "tex_escape"]
