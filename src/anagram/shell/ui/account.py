"""The account of the person in the local UI (layer L1): the overview, the
identity record, devices, guardians, findability, the personal store, the
organizer link, and the recovery kit.

The kit that is not saved yet is a value in the encrypted local vault. It is
never a file in the data directory. The person gets it through the browser
(download or print) and then confirms.
"""

from __future__ import annotations

from contextlib import contextmanager
from typing import TYPE_CHECKING

from anagram.core.errors import ClientError, FormatError
from anagram.core.nodeapi import NodeHTTPError
from anagram.identity.api import KIT_FILE, RecoveryKit, erase_file, parse_kit, recover, validate_ror
from anagram.shell.client import Client
from anagram.shell.ui.errors import UIError

if TYPE_CHECKING:
    from anagram.shell.ui.service import UIService


class AccountUI:
    def __init__(self, ui: UIService) -> None:
        self.ui = ui

    # ------------------------------------------------------------ overview

    def overview(self) -> dict:
        ui = self.ui
        st = ui.state.load()
        task = ui.join.task
        base = {
            "join": task.view() if task else None,
            "joined": ui.joined(),
            "pending_invite": bool(st.get("invite")),
            "signed_in_before": ui.has_identity(),
        }
        # A member signs in again with the key of this computer (no invite).
        base["can_sign_in_again"] = base["signed_in_before"]
        if not base["joined"]:
            return base
        with ui.session() as c:
            me = c.account.whoami()
            ident = me.get("identity") or {}
            lab = None
            if ident.get("lab_id"):
                lab = {
                    "id": ident["lab_id"],
                    "name": c.device.http.call("GET", f"/labs/{ident['lab_id']}", auth=True)[
                        "name"
                    ],
                }
            orcid_mode = c.config.get("identity", {}).get("orcid_mode")
            orcid = c.account.orcid
        ror = ident.get("institution")
        return {
            **base,
            "community": me["community"],
            "details": {"node": me["node"], "subject": me["subject"]},
            "fake_orcid": orcid_mode == "fake",
            "institution": {"id": ror, "name": st.get("institution_name") or ror} if ror else None,
            "kit_saved": bool(st.get("kit_saved")),
            "lab": lab,
            "email": me.get("email"),
            "findable": bool(me.get("findable")),
            "organizer": me.get("role") == "organizer",
            "findable_by_orcid": bool(me.get("findable_by_orcid")),
            "name": ident.get("display_name"),
            "orcid": orcid,
            "setup_done": bool(st.get("kit_saved")) and bool(ror),
        }

    def set_identity(
        self,
        name: str,
        ror: str,
        institution_name: str | None,
        lab_id: str | None = None,
        new_lab: str | None = None,
    ) -> dict:
        ui = self.ui
        name = (name or "").strip()
        if not name:
            raise UIError(400, "Enter your name as colleagues know it.")
        try:
            validate_ror(ror)
        except FormatError as exc:
            raise UIError(400, "Choose your institution from the list.") from exc
        with ui.session() as c:
            if new_lab:
                lab_id = c.labs.lab_create(new_lab.strip())["lab_id"]
            c.account.set_identity(name, institution=ror, lab_id=lab_id or None)
            if lab_id and "My lab" in {r["name"] for r in c.grants.ring_list()}:
                c.grants.ring_add("My lab", [f"lab:{lab_id}"])
        ui.state.update(institution_name=institution_name or ui.institutions.name(ror) or ror)
        ui.people.forget()
        out = self.overview()
        ui.publish("overview.changed")
        return out

    def organizer_link(self) -> dict:
        """A one-time link to the organizer page of the node (an
        organizer needs no ORCID iD). Two minutes, one use."""
        with self.ui.session() as c:
            try:
                got = c.device.http.call("POST", "/admin/enter-link", {}, auth=True)
            except NodeHTTPError as exc:
                raise UIError(
                    403, "Only an organizer of this community can open this page."
                ) from exc
        return {"url": got["url"]}

    # ------------------------------------------------------------- account

    def view(self) -> dict:
        ui = self.ui
        with ui.session() as c:
            me = c.account.whoami()
            c.directory.monitor()
            alerts = c.vault.alerts()
            this = me["this_device"]["ed25519"]
            try:
                gset = c.device.http.call("GET", "/guardians", auth=True)
            except NodeHTTPError as exc:
                if exc.status != 404:
                    raise
                gset = None
            requests = c.guardians.guardian_requests()
        label = ui.people.label
        return {
            "alerts": alerts,
            "devices": [
                {
                    "id": d,
                    "label": "This computer" if d == this else "Another device",
                    "this": d == this,
                }
                for d in me["devices"]
            ],
            "guardians": None
            if gset is None
            else {
                "people": [label(g["subject"]) for g in gset["guardians"]],
                "threshold": gset["threshold"],
            },
            "kit_saved": bool(ui.state.get("kit_saved")),
            "requests": [
                {
                    "check_ok": r["check"] == "ok",
                    "id": r["request_id"],
                    "person": label(r["request"]["subject"]),
                }
                for r in requests
            ],
        }

    def set_findable(self, on: bool) -> dict:
        """'Findable': members who know my email address (or my linked ORCID
        iD) can find me, for example to share work."""
        with self.ui.session() as c:
            r = c.account.set_findable(on)
        return {
            "findable": bool(r.get("findable", r.get("findable_by_orcid"))),
            "findable_by_orcid": bool(r.get("findable_by_orcid")),
        }

    def sync_store(self) -> dict:
        """Send my vault records and an index snapshot to the personal store."""
        with self.ui.session() as c:
            return c.personal.sync_store(snapshot=True)

    def add_device(self, request: str) -> dict:
        with self.ui.session() as c:
            c.account.add_device(request.strip())
        return self.view()

    def set_guardians(self, people: list[str], threshold: int) -> dict:
        with self.ui.session() as c:
            c.guardians.guardians_set(people, threshold=threshold)
        return self.view()

    def approve_guardian(self, request_id: str) -> dict:
        with self.ui.session() as c:
            reqs = {r["request_id"]: r for r in c.guardians.guardian_requests()}
            r = reqs.get(request_id)
            if r is None:
                raise UIError(404, "This request is gone.")
            if r["check"] != "ok":
                raise UIError(409, "This request does not pass the checks. Do not approve it.")
            c.guardians.guardian_approve(request_id)
        return self.view()

    # -------------------------------------------------------- recovery kit

    @contextmanager
    def _kit_client(self):
        """The client for the pending kit, or None if this home has no
        identity. It needs no session (the kit stays readable after a
        sign-out). An old plain kit file moves into the vault and is erased."""
        ui = self.ui
        with ui.lock:
            if not ui.has_identity():
                yield None
                return
            client = Client(ui.home, clock=ui.clock)
            try:
                old = ui.home / KIT_FILE
                if old.exists():
                    text = old.read_text()
                    try:
                        code = parse_kit(text)["recovery code"]
                    except ClientError:
                        code = None
                    if (
                        code
                        and client.account.pending_kit() is None
                        and not ui.state.get("kit_saved")
                    ):
                        client.account.keep_pending_kit(RecoveryKit(text, code))
                    erase_file(old)
                yield client
            finally:
                client.vault.close()

    def recovery_kit(self) -> dict:
        """`pending`: a kit waits for the person to save it. `available` is
        the old name of `pending`."""
        with self._kit_client() as c:
            kit = c.account.pending_kit() if c is not None else None
        if kit is None:
            saved = bool(self.ui.state.get("kit_saved"))
            return {"available": False, "pending": False, "saved": saved}
        return {"available": True, "code": kit.code, "pending": True, "saved": False}

    def recovery_kit_text(self) -> str:
        with self._kit_client() as c:
            kit = c.account.pending_kit() if c is not None else None
        if kit is None:
            raise UIError(404, "Anagram has no recovery kit to save. Make a new recovery kit.")
        return kit.text

    def kit_saved(self) -> dict:
        """The person confirms that the kit is saved. Anagram deletes its copy."""
        with self._kit_client() as c:
            if c is not None:
                c.account.drop_pending_kit()
        self.ui.state.update(kit_saved=True)
        self.ui.publish("overview.changed")
        return {"saved": True}

    def new_recovery_kit(self) -> dict:
        with self.ui.session() as c:
            kit = c.account.make_recovery_kit()
            c.account.keep_pending_kit(kit)
        self.ui.state.update(kit_saved=False)
        return {"code": kit.code}

    def recover(self, kit_text: str) -> dict:
        """Restore the keys of a person on a new computer from the recovery
        kit (the text of the file). The same work as `anagram recover KIT`.
        The kit is not kept: the person has it, so `kit_saved` is true."""

        ui = self.ui
        if not isinstance(kit_text, str) or not kit_text.strip() or len(kit_text) > 20_000:
            raise UIError(400, "Choose the kit file, or paste its text.")
        with ui.lock:
            if ui.has_identity() or (ui.home / "config.json").exists():
                raise UIError(
                    409,
                    "This computer already has Anagram keys. Sign in with them on the first screen.",
                )
            try:
                parse_kit(kit_text)
            except ClientError as exc:
                raise UIError(
                    400, "This is not an Anagram recovery kit. Use the saved file."
                ) from exc
            try:
                client = recover(
                    ui.home,
                    kit_text,
                    transport=ui.transport,
                    clock=ui.clock,
                    open_home=Client.open,
                )
            except NodeHTTPError as exc:
                raise UIError(502, f"The community server said: {exc.detail}") from exc
            except OSError as exc:
                raise UIError(
                    502,
                    "Anagram could not reach the community server. Check your network, then try again.",
                ) from exc
            except (ClientError, FormatError) as exc:
                raise UIError(
                    400,
                    "Anagram could not restore your keys with this kit. Use the newest kit file.",
                ) from exc
            try:
                subject = client.device.subject
            finally:
                client.vault.close()
            ui.state.update(kit_saved=True)
        return {"state": "restored", "subject": subject}
