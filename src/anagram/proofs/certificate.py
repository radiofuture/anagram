"""Proof certificate: one self-contained HTML file for a timestamped finding.

The certificate is a page that a person can read, print, and send. The proof
bundle is inside it (`<script type="application/json" id="anagram-proof">`),
so `anagram verify cert.html` and the verify page of the node check the same
file. The words of the page are a copy of the facts of `verify_bundle`; only
the check of the embedded bundle counts.

Rules:

- The page shows only fields that the bundle opens, and facts from the
  verify report. The name and ORCID iD of the owner are "stated by the
  owner": the bundle does not prove them.
- No script runs. No remote resource. The font and the mark are inline. A
  meta CSP refuses each script and each remote load.
- The print style sheet fits A4 and Letter on one page for up to 8 files.
"""

from __future__ import annotations

import base64
import html
import json
import re
from datetime import UTC, datetime
from importlib import resources
from pathlib import Path
from typing import TYPE_CHECKING, Any

from anagram.core.errors import FormatError
from anagram.proofs.bundle import ProofBundle
from anagram.proofs.log.checkpoint import Checkpoint, open_checkpoint
from anagram.proofs.log.note import NoteError, parse_note
from anagram.proofs.proof import Trust, VerifyReport, verify_bundle

if TYPE_CHECKING:
    from anagram.proofs.ports import FindingSource

_PACKAGE = Path(str(resources.files("anagram")))
FONT = _PACKAGE / "shell" / "ui" / "static" / "brand" / "assets" / "dm-sans.ttf"
CSS = _PACKAGE / "web" / "certificate" / "certificate.css"

#: The id of the script element that holds the bundle.
PROOF_ID = "anagram-proof"
_PROOF_RE = re.compile(
    r'<script type="application/json" id="' + PROOF_ID + r'">(.*?)</script>', re.DOTALL
)
TITLE_MAX = 160
# The CSP of the file itself: no script, nothing from the network.
_CSP = "default-src 'none'; style-src 'unsafe-inline'; font-src data:; img-src data:"

# The four frames of the brand mark (brand/assets/four-squares.svg).
_MARK = (
    '<svg class="mark" viewBox="0 0 1232 90" aria-hidden="true" focusable="false">'
    '<path d="M7 90V7H225V90 M263 0V83H481V0 M519 90V7H969V90 M1007 90V7H1225V90" '
    'fill="none" stroke="currentColor" stroke-width="14" stroke-linejoin="miter"/></svg>'
)

#: The words of the certificate, in one place for the copy pass.
WORDS = {
    "doc_title": "Proof certificate",
    "spine": "Anagram — proof of prior existence",
    "kind": "Proof certificate",
    "statement": "This record existed no later than",
    "no_time": "The time of this record is not proven yet.",
    "checked": "Checked on {date} against the public log of {origin}. All {total} checks passed.",
    "failed": "This proof did not pass all checks when this page was made. Do not trust it.",
    "claim_closed": "The owner did not show the claim.",
    "record": "The record",
    "root": "Finding fingerprint",
    "finding": "Finding ID",
    "version": "Version",
    "hash": "Hash",
    "hash_value": "SHA-256",
    "key": "Signing key",
    "stated": "Stated by the owner",
    "orcid": "ORCID iD",
    "time": "The time",
    "witness": "Witness signature",
    "none": "None",
    "anchors": "Independent time",
    "anchor_none": "None. The time comes from the witness only.",
    "pending": "Pending",
    "fake_label": "Test anchor",
    "not_counted": "Not counted",
    "log": "Public log",
    "entry": "Entry {i}, in a log of {n}",
    "log_key": "Log key",
    "fake": "A test anchor is in this proof. It proves no time. Use this page for tests only.",
    "files": "Files in this record",
    "files_closed": "The owner did not show the files.",
    "file_n": "File {n}",
    "col_name": "Name",
    "col_size": "Size",
    "col_digest": "Content digest",
    "closed": "Not shown",
    "proves": "What this proves",
    "proves_1": "The signing key above signed this record.",
    "proves_2": "The public log of {origin} held the record no later than the time above.",
    "proves_3": "A file whose content digest equals a digest above is a file of this record.",
    "not": "What this does not prove",
    "not_1": "That the owner made the work. It shows only that the key signed the record, and when the log had it.",
    "not_2": "What the files mean.",
    "not_3": "Anything about the parts of the record that this page does not show.",
    "not_4": "The name and ORCID iD. The owner states them. The proof does not check them.",
    "how": "How to check it",
    "how_1": "Keep this file. The proof is inside it.",
    "how_2": "Open {url} and drop this file on the page.",
    "how_3": "With no network:",
    "how_note": "The words on this page are a copy. Only the check of the proof inside it counts.",
    "made": "Made with Anagram on {date}.",
    "save": "Save the proof file",
}


# ------------------------------------------------------------------ load


def load_proof(path: str | Path) -> ProofBundle:
    """A proof bundle from a `.json` bundle file or from a certificate `.html`
    (the embedded bundle). Raises FormatError for a file with no proof."""
    text = Path(path).read_text(encoding="utf-8")
    return proof_from_text(text)


def proof_from_text(text: str) -> ProofBundle:
    """The bundle of a bundle JSON text or of a certificate HTML text."""
    if text.lstrip().startswith("{"):
        return ProofBundle.loads(text)
    found = _PROOF_RE.findall(text)
    if len(found) != 1:
        raise FormatError(
            "this file has no proof" if not found else "this file has more than one proof"
        )
    try:
        return ProofBundle.loads(found[0])
    except (ValueError, KeyError, TypeError) as exc:
        raise FormatError(f"bad proof in the certificate: {exc}") from exc


# ---------------------------------------------------------------- facts


def node_facts(bundle: ProofBundle, trust: Trust | None = None) -> dict:
    """Origin and log key of the checkpoint. With `trust`, the log key is the
    pinned key that signed it ("name+hash"); else only the origin."""
    origin = ""
    try:
        origin = Checkpoint.parse_text(parse_note(bundle.log.checkpoint).text).origin
    except (NoteError, ValueError):
        pass
    log_key = None
    if trust is not None:
        try:
            vc = open_checkpoint(bundle.log.checkpoint, trust.log_keys)
            log_key = f"{vc.log_key.name}+{vc.log_key.key_hash.hex()}"
        except NoteError:
            log_key = None
    return {"origin": origin, "log_key": log_key}


def owner_of(client: FindingSource) -> dict | None:
    """The name and ORCID iD that the owner states, or None
    for a computer that has not joined a node. Best effort: a node that does
    not answer gives the name of the last sign-in."""
    ident = client.config.get("identity") or {}
    if not ident.get("subject"):
        return None
    name = ident.get("profile_name")
    try:
        record = client.device.http.call("GET", "/me", auth=True).get("identity") or {}
        name = record.get("display_name") or name
    except Exception:  # noqa: S110 - the name is optional on the certificate
        pass
    # The identity record holds a ROR ID, not a name: no institution here.
    return {"name": name, "orcid": ident.get("orcid"), "institution": None}


def verify_url(client: FindingSource) -> str | None:
    """The verify page of the node of this computer, or None for a local node."""
    node = client.config.get("node") or {}
    if node.get("mode") != "http" or not node.get("url"):
        return None
    return node["url"].rstrip("/") + "/verify"


def certificate_bundle(
    client: FindingSource, ref: str, *, claim: bool = True, files: bool = True, digests: bool = True
) -> ProofBundle:
    """A bundle with the openings that the owner chose. The finding ID and
    the version are always open; the claim, the file names, and the file
    content digests are open on request."""
    doc = client.findings.opening(ref)
    names = ["finding_id", "version"]
    if claim and doc.finding.fields.get("claim") is not None:
        names.append("claim")
    ev_fields = (["name", "media_type"] if files else []) + (["content"] if digests else [])
    ev = {slot: ev_fields for slot in range(len(doc.evidence))} if ev_fields else {}
    return client.findings.public_bundle(ref, names, ev)


def make_certificate(
    client: FindingSource,
    ref: str,
    *,
    claim: bool = True,
    files: bool = True,
    digests: bool = True,
    name: bool = True,
    now: datetime | None = None,
) -> tuple[str, str, VerifyReport]:
    """(file name, HTML, report) for one finding of this client. The caller
    refuses to give out a certificate whose report is not ok."""
    row = client.vault.find(ref)
    try:
        client.findings.refresh_anchors(row.root)
    except Exception:  # noqa: S110 - the proof is valid without new anchors
        pass
    bundle = certificate_bundle(client, row.root, claim=claim, files=files, digests=digests)
    trust = client.device.trust()
    report = verify_bundle(bundle, trust)
    text = render_certificate(
        bundle,
        report,
        owner=owner_of(client) if name else None,
        verify_url=verify_url(client),
        node=node_facts(bundle, trust),
        now=now,
    )
    return certificate_name(row.root), text, report


def certificate_name(root: str) -> str:
    return f"anagram-certificate-{root[:12]}.html"


# --------------------------------------------------------------- render


def _e(value: Any) -> str:
    return html.escape(str(value), quote=True)


def _date(when: datetime) -> str:
    when = when.astimezone(UTC)
    return f"{when.day} {when:%B %Y}"


def _when(when: datetime) -> str:
    """Full time with seconds. A rounded time would claim an earlier time
    than the proof gives."""
    when = when.astimezone(UTC)
    return f"{_date(when)}, {when:%H:%M:%S} UTC"


def _size(n: int) -> str:
    if n < 1000:
        return f"{n} bytes" if n != 1 else "1 byte"
    for unit, k in (("GB", 1e9), ("MB", 1e6), ("kB", 1e3)):
        if n >= k:
            return f"{n / k:.1f} {unit}"
    return f"{n} bytes"  # pragma: no cover


def _groups(hexs: str, n: int = 4) -> str:
    return " ".join(hexs[i : i + n] for i in range(0, len(hexs), n))


def title_of(bundle: ProofBundle, report: VerifyReport) -> str:
    claim = report.opened.get("claim")
    if isinstance(claim, str) and claim.strip():
        first = claim.strip().splitlines()[0].strip()
        if len(first) > TITLE_MAX:
            first = first[: TITLE_MAX - 1].rstrip() + "…"
        return first
    return f"Finding {bundle.subject.root.hex()[:12]}"


def _anchor_label(label: str) -> str:
    return WORDS["fake_label"] if label.startswith("fake") else label


def _anchor_state(state: str) -> str:
    if state.startswith("valid, "):
        try:
            return _when(datetime.fromisoformat(state.removeprefix("valid, ")))
        except ValueError:
            return state
    if state.startswith("pending"):
        return WORDS["pending"]
    return WORDS["not_counted"]


def _fact(label: str, value: str, *, mono: bool = False) -> str:
    cls = ' class="mono"' if mono else ""
    return f"<div><dt>{_e(label)}</dt><dd{cls}>{value}</dd></div>"


def _files(report: VerifyReport) -> str:
    rows = []
    for slot in sorted(report.evidence):
        fields = report.evidence[slot]
        name = fields.get("name")
        content = fields.get("content") if isinstance(fields.get("content"), dict) else None
        label = name if isinstance(name, str) and name else WORDS["file_n"].format(n=slot + 1)
        size = _e(_size(int(content["size"]))) if content else _e(WORDS["closed"])
        digest = (
            f'<span class="mono">{_e(_groups(str(content["digest"]), 8))}</span>'
            if content
            else _e(WORDS["closed"])
        )
        rows.append(
            f'<tr><td class="n">{slot + 1}</td><td class="name">{_e(label)}</td>'
            f'<td class="size">{size}</td><td class="digest">{digest}</td></tr>'
        )
    if not rows:
        return f'<p class="quiet">{_e(WORDS["files_closed"])}</p>'
    return (
        '<table class="files"><thead><tr><th class="n" scope="col">#</th>'
        f'<th scope="col">{_e(WORDS["col_name"])}</th>'
        f'<th class="size" scope="col">{_e(WORDS["col_size"])}</th>'
        f'<th scope="col">{_e(WORDS["col_digest"])}</th></tr></thead>'
        f"<tbody>{''.join(rows)}</tbody></table>"
    )


def _embedded(bundle: ProofBundle) -> str:
    """The bundle as JSON that is safe inside a script element."""
    text = json.dumps(bundle.to_json(), sort_keys=True, separators=(",", ":"))
    return text.replace("&", "\\u0026").replace("<", "\\u003c").replace(">", "\\u003e")


def _font_face() -> str:
    data = base64.b64encode(FONT.read_bytes()).decode()
    return (
        "@font-face{font-family:'Radiofuture Sans';font-style:normal;font-weight:400;"
        f"src:url(data:font/ttf;base64,{data}) format('truetype')}}"
    )


def render_certificate(
    bundle: ProofBundle,
    report: VerifyReport,
    *,
    owner: dict | None,
    verify_url: str | None,
    node: dict,
    now: datetime | None = None,
) -> str:
    """One HTML file. `owner`: {name, orcid, institution} as the owner states
    them (None to leave them out). `node`: {origin, log_key} (node_facts)."""
    now = now or datetime.now(UTC)
    w = WORDS
    root = bundle.subject.root.hex()
    origin = node.get("origin") or w["none"]
    title = title_of(bundle, report)
    file_name = certificate_name(root)
    proof_name = f"{root[:12]}.proof.json"

    if report.not_after:
        statement = (
            f'<p class="statement">{_e(w["statement"])} '
            f'<strong class="when">{_e(_when(report.not_after))}</strong>.</p>'
        )
    else:
        statement = f'<p class="statement">{_e(w["no_time"])}</p>'
    required = [c for c in report.checks if c.required]
    if report.ok:
        status = (
            '<p class="status">'
            + _e(w["checked"].format(date=_date(now), origin=origin, total=len(required)))
            + "</p>"
        )
    else:
        status = f'<p class="status status--bad" role="alert">{_e(w["failed"])}</p>'

    claim_note = (
        ""
        if isinstance(report.opened.get("claim"), str)
        else f'<p class="quiet">{_e(w["claim_closed"])}</p>'
    )

    record = [_fact(w["root"], _e(_groups(root)), mono=True)]
    finding_id = report.opened.get("finding_id")
    version = report.opened.get("version")
    if isinstance(finding_id, str):
        record.append(_fact(w["finding"], _e(_groups(finding_id)), mono=True))
    if isinstance(version, int):
        record.append(_fact(w["version"], _e(version)))
    record.append(_fact(w["hash"], _e(w["hash_value"])))
    record.append(_fact(w["key"], _e(_groups(report.owner_key or "")), mono=True))
    stated = ""
    if owner and (owner.get("name") or owner.get("orcid")):
        parts = []
        if owner.get("name"):
            parts.append(f'<span class="who">{_e(owner["name"])}</span>')
        if owner.get("institution"):
            parts.append(f"<span>{_e(owner['institution'])}</span>")
        if owner.get("orcid"):
            parts.append(
                f'<span>{_e(w["orcid"])} <span class="mono">{_e(owner["orcid"])}</span></span>'
            )
        stated = (
            f'<div class="stated"><p class="label">{_e(w["stated"])}</p>'
            f"<p>{''.join(parts)}</p></div>"
        )

    time = [
        _fact(
            w["witness"], _e(_when(report.witness_time)) if report.witness_time else _e(w["none"])
        )
    ]
    if report.anchor_notes:
        items = "".join(
            f'<li><span>{_e(_anchor_label(label))}</span> <span class="state">{_e(_anchor_state(state))}</span></li>'
            for label, state in report.anchor_notes
        )
        time.append(_fact(w["anchors"], f'<ul class="anchors">{items}</ul>'))
    else:
        time.append(_fact(w["anchors"], _e(w["anchor_none"])))
    log_lines = [
        _e(origin),
        _e(w["entry"].format(i=bundle.log.leaf_index, n=bundle.log.tree_size)),
    ]
    time.append(_fact(w["log"], "<br>".join(log_lines)))
    if node.get("log_key"):
        time.append(_fact(w["log_key"], _e(node["log_key"]), mono=True))
    fake = any(label.startswith("fake") for label, _ in report.anchor_notes)
    fake_line = f'<p class="warn" role="note">{_e(w["fake"])}</p>' if fake else ""

    nots = [w["not_1"], w["not_2"], w["not_3"]] + ([w["not_4"]] if stated else [])
    how = [f"<li>{_e(w['how_1'])}</li>"]
    if verify_url:
        url = '<span class="url">' + _e(verify_url) + "</span>"
        how.append("<li>" + _e(w["how_2"]).format(url=url) + "</li>")
    how.append(
        f"<li>{_e(w['how_3'])} <code>anagram verify {_e(file_name)}</code>"
        "<code>--file &lt;your file&gt;</code></li>"
    )

    proof_json = _embedded(bundle)
    data_url = "data:application/json;base64," + base64.b64encode(bundle.dumps().encode()).decode()
    css = CSS.read_text(encoding="utf-8")

    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta http-equiv="Content-Security-Policy" content="{_CSP}">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="referrer" content="no-referrer">
<meta name="generator" content="Anagram">
<title>{_e(w["doc_title"])}: {_e(title)}</title>
<style>{_font_face()}
{css}</style>
</head>
<body>
<main class="sheet" aria-labelledby="claim">
<div class="spine" aria-hidden="true"><span>{_e(w["spine"])}</span></div>
<div class="page">
<header class="top">
<p class="brand">{_MARK}<span>Anagram</span></p>
<p class="kind">{_e(w["kind"])}</p>
</header>
<section class="lead">
<h1 id="claim" class="claim">{_e(title)}</h1>
{claim_note}
{statement}
{status}
{fake_line}
</section>
<div class="facts">
<section aria-labelledby="h-record">
<h2 id="h-record">{_e(w["record"])}</h2>
<dl>{"".join(record)}</dl>
{stated}
</section>
<section aria-labelledby="h-time">
<h2 id="h-time">{_e(w["time"])}</h2>
<dl>{"".join(time)}</dl>
</section>
</div>
<section class="filesec" aria-labelledby="h-files">
<h2 id="h-files">{_e(w["files"])}</h2>
{_files(report)}
</section>
<div class="limits">
<section aria-labelledby="h-proves">
<h2 id="h-proves">{_e(w["proves"])}</h2>
<ul>
<li>{_e(w["proves_1"])}</li>
<li>{_e(w["proves_2"].format(origin=origin))}</li>
<li>{_e(w["proves_3"])}</li>
</ul>
</section>
<section aria-labelledby="h-not">
<h2 id="h-not">{_e(w["not"])}</h2>
<ul>{"".join(f"<li>{_e(n)}</li>" for n in nots)}</ul>
</section>
<section aria-labelledby="h-how">
<h2 id="h-how">{_e(w["how"])}</h2>
<ol>{"".join(how)}</ol>
<p class="quiet">{_e(w["how_note"])}</p>
</section>
</div>
<footer class="foot">
<p>{_e(w["made"].format(date=_date(now)))}</p>
<p><a href="{data_url}" download="{_e(proof_name)}">{_e(w["save"])}</a></p>
</footer>
</div>
</main>
<script type="application/json" id="{PROOF_ID}">{proof_json}</script>
</body>
</html>
"""
