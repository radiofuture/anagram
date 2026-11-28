"""Join, sign-in, and sign-out of the local UI (layers L4 and L1).

The join with an invite (`admission.device.join.join`), the sign-in again with
the key of this computer (`client.identity.login`), and the optional ORCID
link run as one task in a thread (`JoinTask`). The page follows the task
state (`GET /api/join`, the event `join.state` of `shell/ui/bridge.py`).
"""

from __future__ import annotations

import hmac
import threading
import time
import urllib.parse
from collections.abc import Callable
from typing import TYPE_CHECKING

from anagram.admission.api import invite_preview, join, parse_invite_url, parse_lab_invite_link
from anagram.core.errors import ClientError, FormatError
from anagram.core.nodeapi import NodeHTTPError
from anagram.identity.api import (
    KIT_FILE,
    Browser,
    erase_file,
    login,
)
from anagram.shell.client import Client
from anagram.shell.ui.errors import UIError, plain_error
from anagram.shell.ui.sharing import DEFAULT_RINGS

if TYPE_CHECKING:
    from anagram.shell.ui.service import UIService

SIGNIN_TIMEOUT = 900.0


def _valid_authorize_url(
    url: object, node_url: str | None = None, orcid_mode: str | None = None
) -> bool:
    if not isinstance(url, str) or not url:
        return False
    p = urllib.parse.urlsplit(url)
    if p.scheme == "https" and p.netloc in ("orcid.org", "sandbox.orcid.org"):
        return True
    if node_url and orcid_mode in (None, "fake"):
        node = urllib.parse.urlsplit(node_url)
        fake_prefix = f"{node.path.rstrip('/')}/fake-orcid/"
        if (
            p.scheme in ("http", "https")
            and (p.scheme, p.netloc) == (node.scheme, node.netloc)
            and p.path.startswith(fake_prefix)
        ):
            return True
    return False


class UIBrowser(Browser):
    """The ORCID step for the local UI. `open(url)` hands the sign-in address
    to the web page (the page goes there in the same tab) and waits until the
    node sends the person back to this UI's /auth/callback."""

    def __init__(
        self,
        return_to: str,
        timeout: float = SIGNIN_TIMEOUT,
        *,
        node_url: str | None = None,
        orcid_mode: str | None = None,
    ) -> None:
        self.return_to = return_to
        self.timeout = timeout
        self.node_url = node_url
        self.orcid_mode = orcid_mode
        self.url: str | None = None
        self.result: dict | None = None
        self._cancelled = False
        self._ready = threading.Event()
        self._back = threading.Event()

    def open(self, url: str) -> dict:
        if not _valid_authorize_url(url, self.node_url, self.orcid_mode):
            raise ClientError("The community server returned an unexpected sign-in address.")
        self.url = url
        self._ready.set()
        if not self._back.wait(self.timeout):
            raise ClientError("sign-in timed out. Start again.")
        if self._cancelled:
            raise ClientError("Sign-in cancelled.")
        return self.result or {}

    def wait_url(self, timeout: float) -> str | None:
        self._ready.wait(timeout)
        return self.url

    def finish(self, params: dict) -> None:
        self.result = params
        self._back.set()

    def cancel(self) -> None:
        self._cancelled = True
        self._ready.set()
        self._back.set()


class JoinTask:
    def __init__(self, browser: UIBrowser, timeout: float = SIGNIN_TIMEOUT) -> None:
        self.browser = browser
        # starting, signin, code, working, joined, linked, pending_device, error
        self.state = "starting"
        self.error: str | None = None
        self.device_request: str | None = None
        self.thread: threading.Thread | None = None
        self.timeout = timeout
        self.email_hint: str | None = None  # a reader invite to an email address
        self._code: str | None = None
        self._cancelled = False
        self._code_given = threading.Event()

    def code_sent(self, hint: str) -> None:
        self.email_hint = hint

    def wait_code(self) -> str:
        """The join waits here until the person types the code."""
        if not self._code_given.wait(self.timeout):
            raise ClientError("The code was not entered in time. Start again.")
        if self._cancelled:
            raise ClientError("Join cancelled.")
        return self._code or ""

    def give_code(self, code: str) -> bool:
        if self.email_hint is None or self._code_given.is_set():
            return False
        self._code = code
        self._code_given.set()
        return True

    def cancel(self) -> None:
        self._cancelled = True
        self.browser.cancel()
        self._code_given.set()

    def view(self) -> dict:
        state = self.state
        if state == "starting" and self.browser.url:
            state = "signin"
        if state == "signin" and self.browser.result is not None:
            state = "working"
        if state == "starting" and self.email_hint is not None:
            state = "working" if self._code_given.is_set() else "code"
        return {
            "authorize_url": self.browser.url if state == "signin" else None,
            "device_request": self.device_request,
            "email_hint": self.email_hint if state == "code" else None,
            "error": self.error,
            "state": state,
        }


class _Linked:
    """The result of an ORCID link task."""

    status = "linked"
    client = None


class JoinUI:
    def __init__(self, ui: UIService) -> None:
        self.ui = ui
        self.task: JoinTask | None = None

    # ------------------------------------------------------------- invite

    def prepare(
        self,
        invite: str,
        login_hint: str | None = None,
        name: str | None = None,
        sources: list[dict] | None = None,
    ) -> None:
        """Store an invite (and for the demo: an ORCID hint, a name, and sources
        to add after the join). The person still clicks every step."""
        self.ui.state.update(
            invite=invite, login_hint=login_hint, display_name=name, pending_sources=sources or []
        )

    def invite_info(self) -> dict:
        """The stored invite for the welcome screen: `community` (its name)
        and `host` (the host name of the server) are shown one time; `lab`
        is the lab name of a lab invite."""
        st = self.ui.state.load()
        out = {"invite": st.get("invite"), "name": st.get("display_name")}
        if st.get("invite"):
            try:
                inv = parse_invite_url(st["invite"])
            except FormatError:
                try:  # a lab invite link
                    inv = parse_lab_invite_link(st["invite"])["auth"]
                    out["lab"] = inv["lab_name"]
                except FormatError:
                    inv = None
            if inv is not None:
                out["community_url"] = inv["node_url"]
                out["community"] = inv["community"]
                out["host"] = urllib.parse.urlsplit(inv["node_url"]).hostname
            out.update(self._invite_contact(st["invite"]))
        return out

    def _invite_contact(self, invite: str) -> dict:
        """For an invite to a named person: `contact` ("email" or
        "orcid") and `email_hint`. The form then does not ask for the
        address. A fault leaves the plain form."""

        try:
            got = invite_preview(invite, self.ui.transport)
        except (ClientError, NodeHTTPError, OSError, FormatError):
            return {"contact": None, "email_hint": None}
        return {"contact": got.get("contact"), "email_hint": got.get("email_hint")}

    # -------------------------------------------------------------- tasks

    def start_join(
        self,
        invite: str | None = None,
        name: str | None = None,
        email: str | None = None,
    ) -> dict:
        """The join with the invite only: the name, and the email address
        when the invite was not sent to one. No ORCID step. The old ORCID join
        of `POST /api/join` is removed."""
        ui = self.ui
        st = ui.state.load()
        invite = (invite or st.get("invite") or "").strip()
        if not invite:
            raise UIError(400, "Paste the invite link from your community organizer.")
        try:
            inv_doc = parse_invite_url(invite)
            node_url = inv_doc["node_url"]
        except FormatError:
            try:  # a lab invite link
                inv_doc = parse_lab_invite_link(invite)
                node_url = inv_doc["auth"]["node_url"]
            except FormatError as exc:
                raise UIError(
                    400, "This is not an Anagram invite link. Copy the full link."
                ) from exc
        name = (name or "").strip() or st.get("display_name")
        if not name and not ui.has_identity():
            raise UIError(400, "Enter your name as colleagues know it.")
        email = (email or "").strip() or None
        if email and ("@" not in email or " " in email or len(email) > 254):
            raise UIError(400, "Type an email address, for example name@lab.org.")
        ui.state.update(invite=invite, display_name=name)

        def run(browser: UIBrowser, task: JoinTask):
            result = join(
                ui.home,
                invite,
                transport=ui.transport,
                browser=browser,  # only for an invite to an ORCID iD
                login_hint=st.get("login_hint"),
                display_name=name,
                clock=ui.clock,
                method="invite",
                stated_email=email,
                email_code=task.wait_code,
                on_code_sent=task.code_sent,
                open_home=Client.open,
            )
            if result.status != "pending_device":
                # The join used the invite (a lab invite also joined the lab).
                pending = ui.state.get("pending_invite") or {}
                if pending.get("url") == invite:
                    ui.state.update(pending_invite=None)
            return result

        return self._start(run, node_url=node_url)

    def start_signin(self) -> dict:
        """Sign in again without an invite (a member whose session ended).
        The client config pins the node key; the node checks membership."""
        ui = self.ui
        if not ui.has_identity():
            raise UIError(409, "Join your community first with the invite link.")

        def run(browser: UIBrowser, task: JoinTask):
            # The key of this computer: no ORCID and no email step.
            return login(ui.home, transport=ui.transport, clock=ui.clock, open_home=Client.open)

        return self._start(run)

    def give_code(self, code: str) -> dict:
        """The code from the email of a reader invite."""
        code = (code or "").strip()
        if not code.isdigit() or len(code) != 8:
            raise UIError(400, "Type the 8 digits from the email.")
        task = self.task
        if task is None or not task.give_code(code):
            raise UIError(409, "No join waits for a code. Start again.")
        return task.view()

    def start_link_orcid(self) -> dict:
        """Link an ORCID iD (optional). The page goes to ORCID and comes
        back; the task then ends in the state `linked`."""
        ui = self.ui
        if not ui.joined():
            raise UIError(409, "Join a community first.")
        with ui.session() as c:
            node_url = c.config.get("node", {}).get("url")
            orcid_mode = c.config.get("identity", {}).get("orcid_mode")

        def run(browser: UIBrowser, task: JoinTask):
            with ui.open_client() as c:
                c.account.link_orcid(browser, login_hint=ui.state.get("login_hint"))
            ui.people.forget()
            return _Linked()

        return self._start(run, node_url=node_url, orcid_mode=orcid_mode)

    def _start(
        self,
        fn: Callable[[UIBrowser, JoinTask], object],
        *,
        node_url: str | None = None,
        orcid_mode: str | None = None,
    ) -> dict:
        """Run a join, a sign-in, or an ORCID link in a thread. The page
        follows the task (`join.state`)."""
        with self.ui.lock:
            if self.task and self.task.state in ("starting", "working"):
                return self.task.view()
            browser = UIBrowser(self.ui.return_to, node_url=node_url, orcid_mode=orcid_mode)
            task = JoinTask(browser)
            self.task = task

        def run() -> None:
            try:
                r = fn(browser, task)
                if r.status == "linked":
                    task.state = "linked"
                    return
                r.client.close()
                if r.status == "pending_device":
                    task.device_request = r.device_request
                    task.state = "pending_device"
                    return
                task.state = "working"
                self._after_join()
                task.state = "joined"
            except Exception as exc:  # shown to the person
                task.error = plain_error(exc)
                task.state = "error"

        task.thread = threading.Thread(target=run, daemon=True)
        task.thread.start()
        # Wait a short time for the first visible state: the ORCID address,
        # the code step, or the end of a join that needs neither.
        deadline = time.monotonic() + 5.0
        while time.monotonic() < deadline and task.view()["state"] == "starting":
            if task.browser.wait_url(0.05) or not task.thread.is_alive():
                break
        return task.view()

    def cancel(self) -> dict:
        """Cancel an in-progress join or sign-in so the user can start again."""
        with self.ui.lock:
            task = self.task
            self.task = None
        if task is not None:
            task.cancel()
        idle = {"state": "idle"}
        self.ui.publish("join.state", idle)
        return idle

    def finish_signin(self, params: dict) -> bool:
        """The ORCID redirect came back to `/auth/callback`."""
        task = self.task
        if task is None or task.browser.url is None or task.browser.result is not None:
            return False
        got_state = params.get("state")
        if not got_state or not params.get("code"):
            return False
        expected = urllib.parse.parse_qs(urllib.parse.urlsplit(task.browser.url).query).get(
            "state", [None]
        )[0]
        if not expected or not hmac.compare_digest(str(got_state), str(expected)):
            return False
        task.browser.finish({"code": params["code"], "state": got_state})
        return True

    def status(self) -> dict:
        return self.task.view() if self.task else {"state": "idle"}

    def logout(self) -> dict:
        """Sign out: end the node session and remove it from this computer.
        Keys and findings stay. The key of this computer signs in again."""
        with self.ui.session() as c:
            c.account.logout()
        self.task = None
        self.ui.publish("overview.changed")
        return {"signed_out": True}

    def _after_join(self) -> None:
        """Default rings and the sources that wait for the join (demo)."""
        ui = self.ui
        with ui.session() as c:
            if ui.state.get("kit_saved"):
                # A sign-in again makes a new kit. The person has a saved kit,
                # so do not keep a second secret on this computer.
                c.account.drop_pending_kit()
                erase_file(ui.home / KIT_FILE)
            have = {r["name"] for r in c.grants.ring_list()}
            for name, members in DEFAULT_RINGS:
                if name not in have:
                    c.grants.ring_create(name)
                    if members:
                        c.grants.ring_add(name, members)
        pending = ui.state.get("pending_sources") or []
        if pending:
            for src in pending:
                try:
                    ui.sources.add({"kind": src["kind"], "path": src.get("path")}, refresh=False)
                except UIError:
                    continue
            ui.state.update(pending_sources=[])
            ui.sources.refresh()
