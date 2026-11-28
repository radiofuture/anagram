"""Matching through the network enclave, in the app (spec/pack.md 8,
spec/enclave-messages.md, spec/network.md 6.6).

`EnclaveMatching` is what the person does, on top of `EnclaveClient`:

1. **Draft.** The beacon draft of the `profile` lens (OFFERS and WANTS, own
   sentences) or lines that the person types or edits. Nothing leaves.
2. **Approve.** The person approves the lines and the consent statement of
   the release that the app checked. The approval time goes into the pack.
3. **Daily upload.** Each UTC day: a fresh member credential from the node
   (the request is signed by the person key; the proof comes from a
   cosigned checkpoint), then a new pack with matching on, or a cover with
   matching off (after the first upload), so the node sees the same
   traffic either way. Then the day's slot, the answers that are due, and
   the receipts.
4. **Cards.** A proposal shows its match type and the person's own lines
   that the decision used (card option (a)): no peer text, no score. A
   reveal shows the peer's card and the roster record of the peer's node.
5. **Answer.** Yes (with the person's reveal card), no, or not now. The
   person has 21 days (three times `answer_day`); the answer goes out at
   the next of three checkpoints, and a filler goes out at the others
   (enclave-messages.md 5.3).
6. **Weekly cap.** The person may ask for fewer proposals a week than the
   network allows (`weekly_cap_max`); the default is 3.
7. **Matching off.** A withdrawal; the enclave deletes the pack and keeps a
   tombstone. A new "on" needs a new approval.

State is in the vault key-value table (`enclave/...`, encrypted on disk):
settings, draft, approval, versions, open requests and their response
keys, items. The person key (`person-ed25519`) and the reply key are in the
keystore. The app reads the enclave log at the URL of the settings and
pins the keys of `devnet.json` (`simulated` profile: development only).
"""

from __future__ import annotations

import secrets
import ssl
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import asdict, dataclass, field
from typing import TYPE_CHECKING

import httpx

from anagram.core.canonical import JsonObject, canonical_json
from anagram.core.crypto import hpke
from anagram.core.crypto.signing import SigningKey
from anagram.core.errors import ClientError
from anagram.core.keyvalue import JsonKeys, KeyValue
from anagram.network.formats import enclave as m
from anagram.network.formats import pack as packs
from anagram.network.formats.roster import credential_request
from anagram.network.formats.strict import DAY, Refused, fmt_time
from anagram.network.matching.app.enclave_client import (
    RESEAL,
    EnclaveClient,
    Pending,
    pack_doc,
)
from anagram.network.matching.hosting.clients import HttpLog
from anagram.network.matching.trust import descriptor as dsc
from anagram.network.matching.trust.bundle import StaleView
from anagram.network.matching.trust.pins import Pins

if TYPE_CHECKING:
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

    from anagram.identity.api import Device

PERSON_KEY = "person-ed25519"
REPLY_KEY = "enclave-reply-x25519"
LENS_TYPES = {  # lens match types -> pack match types (spec/pack.md 3.3)
    "T1": "research_fit",
    "T2": "method_help",
    "T3": "instrument_access",
    "T4": "data_material_share",
    "T5": "replication",
    "T6": "co_supervision",
}
MAX_LINES = 5  # a person beacon: at most 5 offers and 5 wants
CHOICES = ("yes", "no", "not_now")
TIMEOUT = 30.0
KEEP_DAYS = 30  # items and receipts on the screen (a proposal lives 22 days at most)
NOT_SET_UP = "Matching through the network enclave is not set up in this app."


class EnclaveNotSetUp(ClientError):
    def __init__(self) -> None:
        super().__init__(NOT_SET_UP)


def pack_lines(draft: JsonObject) -> dict[str, list[JsonObject]]:
    """The approved beacon lines as pack lines (pack.md 3.4): IDs o01.. and
    w01.., the lens match types as pack match types, no concepts."""
    out: dict[str, list[JsonObject]] = {"offers": [], "wants": []}
    for side, prefix in (("offers", "o"), ("wants", "w")):
        lines = draft.get(side) or []
        if not isinstance(lines, list) or len(lines) > MAX_LINES:
            raise ClientError(f"{side}: at most {MAX_LINES} lines")
        for n, line in enumerate(lines, start=1):
            text = " ".join(str(line.get("text", "")).split())
            types = sorted(
                {LENS_TYPES[t] for t in line.get("match_types") or ["T1"] if t in LENS_TYPES}
            )
            item = {
                "class": line.get("class", "method"),
                "concepts": [],
                "id": f"{prefix}{n:02d}",
                "scope": line.get("scope", "both"),
                "text": text,
                "types": types or ["research_fit"],
            }
            if item["class"] not in packs.CLASSES or item["scope"] not in packs.SCOPES:
                raise ClientError(f"{side} line {n}: unknown class or scope")
            if not 1 <= len(text) <= 140:
                raise ClientError(f"{side} line {n}: 1 to 140 characters")
            out[side].append(item)
    if not out["offers"] and not out["wants"]:
        raise ClientError("approve at least one line")
    return out


def typed_draft(offers: list[str], wants: list[str]) -> JsonObject:
    """A beacon draft from typed texts (for example the lines that an
    assistant proposes): the default class, scope and match type of each
    line, with the checks of an approval."""
    draft: JsonObject = {
        "offers": [{"class": "method", "scope": "both", "text": t} for t in offers],
        "wants": [{"class": "skill", "scope": "both", "text": t} for t in wants],
    }
    pack_lines(draft)
    return draft


def charter(lines: dict[str, list[JsonObject]], weekly_cap: int) -> JsonObject:
    """Every match type of the lines, with no inside/outside rule, and the
    person's weekly cap (pack.md 3.3)."""
    types = sorted({t for side in lines.values() for line in side for t in line["types"]})
    return {
        "disclosure": "d0",
        "protocols": types,
        "rules": dict.fromkeys(types, "any"),
        "weekly_cap": weekly_cap,
    }


def _prune(st: JsonObject, today: int) -> None:
    """Keep `KEEP_DAYS` of items, receipts and packs (the lines of a card).
    A pack version is a time in milliseconds (pack.md 8)."""
    since = today - KEEP_DAYS
    st["items"] = [i for i in st["items"] if i["day"] > since]
    st["receipts"] = {d: r for d, r in st["receipts"].items() if r["day"] > since}
    st["packs"] = {v: ln for v, ln in st["packs"].items() if int(v) // 1000 // DAY > since}


def default_connect(base_url: str, token: str | None) -> httpx.Client:
    """An HTTP client of the node with the member session. The system trust
    store (and SSL_CERT_FILE) checks the node's certificate."""
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    return httpx.Client(
        base_url=base_url, headers=headers, timeout=TIMEOUT, verify=ssl.create_default_context()
    )


STALE_VIEW_TEXT = (
    "Anagram sends nothing now: its view of the enclave log is more than an hour "
    "old, so it could miss a revoked release. It tries again soon."
)


def remote_fault(exc: Exception) -> ClientError:
    """What the person sees when the work with the node or the log stops."""
    if isinstance(exc, StaleView):
        return ClientError(STALE_VIEW_TEXT)
    return ClientError(
        f"the matching enclave cannot be reached or checked now ({type(exc).__name__})"
    )


@dataclass
class EnclaveMatching:
    device: Device  # keystore, http (node URL and session)
    kv: KeyValue
    clock: Callable[[], float]
    connect: Callable[[str, str | None], httpx.Client] = default_connect
    # The development clock (`ANAGRAM_DEV_CLOCK_FILE`): used only while the
    # settings pin a development network (a `dev_root`); see `now`.
    dev_clock: Callable[[], float] | None = None
    # One HTTP client for each (URL, session) for the life of this object.
    _clients: dict[tuple[str, str | None], httpx.Client] = field(
        default_factory=dict, init=False, repr=False
    )

    @property
    def _keys(self) -> JsonKeys:
        return JsonKeys(self.kv, "enclave/", sort_keys=True)

    def _load(self) -> JsonObject:
        st = self._keys.load("state") or {}
        st.setdefault("on", False)
        st.setdefault("enrolled", False)
        for name in ("responses", "unconfirmed", "pending", "receipts", "packs", "sent", "bodies"):
            st.setdefault(name, {})
        st.setdefault("items", [])
        st.setdefault("version", 0)
        st.setdefault("weekly_cap", packs.WEEKLY_CAP_DEFAULT)
        return st

    def _save(self, st: JsonObject) -> None:
        self._keys.dump("state", st)

    def now(self) -> int:
        if self.dev_clock is not None and self._development_network():
            return int(self.dev_clock())
        return int(self.clock())

    def _development_network(self) -> bool:
        s = self.settings()
        pins = s.get("pins") if s else None
        return isinstance(pins, dict) and bool(pins.get("dev_root"))

    def _connect(self, url: str, token: str | None) -> httpx.Client:
        key = (url, token)
        if key not in self._clients:
            self._clients[key] = self.connect(url, token)
        return self._clients[key]

    def close(self) -> None:
        """Close the HTTP clients of the node and the log."""
        for client in self._clients.values():
            client.close()
        self._clients.clear()

    # ---- settings -------------------------------------------------------------

    def settings(self) -> JsonObject | None:
        doc: JsonObject | None = self._keys.load("settings")  # written by `set_settings`
        return doc

    def set_settings(self, log_url: str, pins: JsonObject) -> JsonObject:
        """The enclave log URL and the pins of the network (devnet.json)."""
        if not str(log_url).startswith(("https://", "http://")):
            raise ClientError("the log URL must be http(s)")
        try:
            Pins.from_json(pins)
        except (KeyError, TypeError, ValueError) as exc:
            raise ClientError(f"these are not the pins of a network: {exc}") from exc
        doc = {"log_url": str(log_url).rstrip("/"), "pins": pins}
        self._keys.dump("settings", doc)
        return doc

    def _pins(self) -> tuple[Pins, str]:
        s = self.settings()
        if not s:
            raise EnclaveNotSetUp
        return Pins.from_json(s["pins"]), s["log_url"]

    # ---- keys and the client ---------------------------------------------------

    def person_key(self) -> SigningKey:
        """The person key (network.md 4), made at the first use."""
        ks = self.device.keystore
        return SigningKey.from_seed(ks.get_or_create(PERSON_KEY, lambda: secrets.token_bytes(32)))

    def _reply(self) -> X25519PrivateKey:
        ks = self.device.keystore
        raw = ks.get_or_create(REPLY_KEY, lambda: hpke.private_bytes(hpke.generate()))
        return hpke.private_from_bytes(raw)

    def _node(self) -> httpx.Client:
        http = self.device.http
        return self._connect(http.base_url, http.token)

    def _client(self, st: JsonObject) -> EnclaveClient:
        pins, log_url = self._pins()
        log = HttpLog(pins.origin, pins.roots, self._connect(log_url, None))
        return EnclaveClient(
            subject=self.person_key(),
            reply=self._reply(),
            node=self._node(),
            roots=pins.roots,
            log=log,
            clock=self.now,
            responses={
                d: hpke.private_from_bytes(bytes.fromhex(k)) for d, k in st["responses"].items()
            },
            pending={p: Pending(**v) for p, v in st["pending"].items()},
            unconfirmed={d: (r, bytes.fromhex(raw)) for d, (r, raw) in st["unconfirmed"].items()},
            bodies={d: (r, cls, bytes.fromhex(b)) for d, (r, cls, b) in st["bodies"].items()},
        )

    def _keep(self, st: JsonObject, c: EnclaveClient) -> None:
        st["unconfirmed"] = {d: [r, raw.hex()] for d, (r, raw) in c.unconfirmed.items()}
        st["responses"] = {
            d: hpke.private_bytes(k).hex() for d, k in c.responses.items() if d in c.unconfirmed
        }
        st["pending"] = {p: asdict(v) for p, v in c.pending.items()}
        st["bodies"] = {d: [r, cls, b.hex()] for d, (r, cls, b) in c.bodies.items()}
        today = self.now() // DAY
        st["sent"] = {d: st["sent"].get(d, today) for d in c.unconfirmed}

    # ---- draft and approval --------------------------------------------------

    def set_draft(self, draft: JsonObject) -> JsonObject:
        """Keep the beacon draft (lens lines, edited or typed). Not sent."""
        pack_lines(draft)  # the same checks as at approval
        st = self._load()
        kept: JsonObject = {"offers": draft.get("offers") or [], "wants": draft.get("wants") or []}
        st["draft"] = kept
        self._save(st)
        return kept

    @contextmanager
    def _remote(self) -> Iterator[tuple[JsonObject, EnclaveClient]]:
        """The state and a client for work with the node and the log. The
        state is kept also when the work stops half way, so the response key
        of each sent request stays. Remote faults become `ClientError`."""
        st = self._load()
        c = self._client(st)
        try:
            yield st, c
        except (Refused, httpx.HTTPError) as exc:  # NotSealable is a refusal too
            raise remote_fault(exc) from exc
        finally:
            self._keep(st, c)
            self._save(st)

    def consent(self) -> JsonObject:
        """The consent statement of the release that the app checked."""
        with self._remote() as (_, c):
            target = c.refresh()
        step = target.matching["answer_day"]
        return {
            "answer_day": step,
            "answer_days": [step * k for k in range(1, m.CHECKPOINTS + 1)],
            "statement": target.matching["consent_statement"],
            "statement_hash": dsc.statement_hash(target.descriptors["matching"][0]),
            "weekly_cap_max": target.matching["weekly_cap_max"],
        }

    def set_weekly_cap(self, value: object) -> JsonObject:
        """The person's weekly cap: 1 to the network's `weekly_cap_max`.
        It goes out with the next pack; the enclave also applies the
        network maximum."""
        top = self.consent()["weekly_cap_max"]
        if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= top:
            raise ClientError(f"the weekly cap is 1 to {top} on this network")
        st = self._load()
        st["weekly_cap"] = value
        self._save(st)
        return self.status()

    def approve(self, statement_hash: str) -> JsonObject:
        """The person approves the draft lines and the statement whose hash
        the UI showed. A changed release needs a new approval."""
        st = self._load()
        if not st.get("draft"):
            raise ClientError("make or type a draft first")
        if statement_hash != self.consent()["statement_hash"]:
            raise ClientError("the consent statement changed; read it again")
        lines = pack_lines(st["draft"])
        st = self._load()
        approved: JsonObject = {"at": self.now(), "lines": lines, "statement_hash": statement_hash}
        st["approved"] = approved
        self._save(st)
        return approved

    # ---- on, off, and the day ------------------------------------------------

    def turn_on(self) -> JsonObject:
        """Matching on: a pack goes out now, also on a day with a cover."""
        st = self._load()
        if not st.get("approved"):
            raise ClientError("approve your lines and the consent first")
        st["on"], st["enrolled"], st["uploaded_day"] = True, True, None
        self._save(st)
        return self.run()

    def turn_off(self) -> JsonObject:
        """Matching off: a withdrawal (enclave-messages.md 7.1). The approval
        ends; a new "on" needs a new one. From the next day, a cover goes
        out in place of the pack."""
        with self._remote() as (st, c):
            if st["on"]:
                st["version"] = self._version(st)
                c.refresh()
                c.withdraw(st["version"])
                st["on"], st["approved"] = False, None
        return self.status()

    def _version(self, st: JsonObject) -> int:
        """pack.md 8: max(last + 1, Unix milliseconds of now)."""
        last: int = st["version"]
        return max(last + 1, self.now() * 1000)

    def _credential(self, c: EnclaveClient) -> JsonObject:
        """A fresh member credential with its log proof (network.md 6.6)."""
        node = c.node.get("/net/node")
        node.raise_for_status()
        device = self.device.device_key().public_bytes().hex()
        req = credential_request(
            c.subject, device, node.json()["id"], secrets.token_hex(16), self.now()
        )
        r = c.node.post("/net/credential", content=canonical_json(req))
        if r.status_code != 200:
            raise ClientError(f"the node gave no credential ({r.status_code})")
        got = r.json()
        proof = c.node.get(f"/net/credential/{got['hash']}/proof")
        if proof.status_code != 200:
            raise ClientError("the credential is not in a cosigned checkpoint yet; try again")
        return {**got["credential"], "log": proof.json()["log"]}

    def _upload(self, st: JsonObject, c: EnclaveClient) -> None:
        cred = self._credential(c)
        target = c.refresh()
        if not st["on"]:
            c.cover(cred)
            return
        approved = st["approved"]
        st["version"] = self._version(st)
        cap = min(st["weekly_cap"], target.matching["weekly_cap_max"])
        doc = pack_doc(
            c.subject,
            c.reply_key,
            cred,
            target,
            approved["lines"],
            charter(approved["lines"], cap),
            st["version"],
            self.now(),
            approved["at"],
        )
        st["packs"][str(st["version"])] = approved["lines"]
        c.upload_pack(doc)

    def run(self) -> JsonObject:
        """The work of the day: the upload (once a UTC day), today's slot,
        the answers that are due, and the receipts of open requests."""
        today = self.now() // DAY
        with self._remote() as (st, c):
            if st["enrolled"] and st.get("uploaded_day") != today:
                self._upload(st, c)
                st["uploaded_day"] = today
            if st["enrolled"] and not any(i["day"] == today for i in st["items"]):
                item = c.slot(today)
                if item is not None:
                    st["items"].append({"day": today, "item": item})
            c.send_due()
            # A request with no receipt since an earlier day was lost in a
            # restart of the writer: the same bytes again (4.4).
            c.resend(d for d, day in st["sent"].items() if day < today)
            for digest in sorted(c.unconfirmed):
                receipt = c.receipt(digest)
                if receipt is not None and receipt.get("reason") in RESEAL:
                    c.reseal(digest)
                elif receipt is not None:
                    st["receipts"][digest] = {
                        "day": today,
                        "reason": receipt.get("reason"),
                        "status": receipt["status"],
                    }
            _prune(st, today)
        return self.status()

    # ---- cards and answers -----------------------------------------------------

    def answer(self, proposal: str, choice: str, card: JsonObject | None = None) -> JsonObject:
        """Record the choice; it goes out at the next checkpoint (5.3)."""
        if choice not in CHOICES:
            raise ClientError(f"choice must be one of {CHOICES}")
        st = self._load()
        if proposal not in st["pending"]:
            raise ClientError("no open proposal with this ID")
        if choice == "yes":
            try:
                m.check_card(card)
            except Refused as exc:
                raise ClientError(f"the reveal card: {exc}") from exc
        p = st["pending"][proposal]
        if p["answered"]:
            raise ClientError("your answer to this proposal went out already")
        p["choice"], p["card"] = choice, card if choice == "yes" else None
        self._save(st)
        return self.status()

    def cards(self, st: JsonObject) -> list[JsonObject]:
        out = []
        for entry in st["items"]:
            item = entry["item"]
            card: JsonObject = {"day": entry["day"], "kind": item["kind"]}
            if item["kind"] == "proposal":
                lines = st["packs"].get(str(item["pack_version"])) or {}
                text = {ln["id"]: ln["text"] for side in lines.values() for ln in side}
                pending = st["pending"].get(item["id"])
                card.update(
                    expires=item["expires"],
                    id=item["id"],
                    reasons=[text.get(r, r) for r in item["reasons"]],
                    type=item["type"],
                    choice=_choice(pending),
                    answer_by=item["checkpoints"][-1],
                    next_checkpoint=_next_checkpoint(pending),
                )
            elif item["kind"] == "reveal":
                card.update(
                    card_of_peer=item["card"],
                    id=item.get("proposal"),  # the proposal that led here: one ID per reveal
                    node=item["node"],
                    type=item["type"],
                )
            if item["kind"] != "empty":
                out.append(card)
        return out

    def status(self) -> JsonObject:
        st = self._load()
        approved, draft = st.get("approved"), st.get("draft")
        return {
            "approved": bool(approved),
            # The draft is the approved text: an edit after the approval
            # needs a new approval before it can go out.
            "draft_approved": bool(approved and draft and _same_lines(draft, approved)),
            "cards": self.cards(st),
            "draft": st.get("draft"),
            "enrolled": st["enrolled"],
            "on": st["on"],
            "open_requests": len(st["unconfirmed"]),
            "receipts": sorted(
                st["receipts"].values(), key=lambda r: (r["status"], r["reason"] or "")
            ),
            "set_up": self.settings() is not None,
            "uploaded_day": st.get("uploaded_day"),
            "weekly_cap": st["weekly_cap"],
        }


def _same_lines(draft: JsonObject, approved: JsonObject) -> bool:
    try:
        return bool(pack_lines(draft) == approved["lines"])
    except (ClientError, KeyError, TypeError, ValueError):
        return False


def _choice(pending: JsonObject | None) -> str:
    """`sent` after the answer went out; `unset` before the person chose."""
    if pending is None or pending["answered"]:
        return "sent"
    return pending["choice"] or "unset"


def _next_checkpoint(pending: JsonObject | None) -> str | None:
    if pending is None or pending["done"] >= len(pending["checkpoints"]):
        return None
    return fmt_time(pending["checkpoints"][pending["done"]] * DAY)
