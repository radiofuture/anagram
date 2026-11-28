"""The task `lab.watch`.

One turn of the task:

1. Long poll `GET /labs/changes` (at most `labs.poll_wait` seconds). The
   first turn, and a turn after `FULL_EVERY_S`, sync all labs: a person who
   was removed gets no row in the change feed of that lab.
2. `lab_sync` for the labs that changed, then `labspace.sync_index`: lab
   sources, withdraws, `publish_pending` for each source in a lab space (a
   new version of a source goes into the lab space), and a scan of the lab
   sources when a lab changed.
3. Compare the cache before and after, and publish the lab events.

The task starts no thread (the `TaskRunner` gives it one). A failed turn
raises, and the next wait is `poll_min` seconds times two for each failure
in a row, at most 5 minutes. Client config (`config.json`, key `labs`):
`{"poll_wait": 25, "poll_min": 5}`.
"""

from __future__ import annotations

import contextlib
import http.client
import json
import socket
import threading
import time
import urllib.parse
from collections.abc import Callable
from typing import TYPE_CHECKING, Any

from anagram.core.nodeapi import NodeHTTPError
from anagram.network.api import (
    sync_lab_index,
)

if TYPE_CHECKING:
    from anagram.shell.ui.service import UIService

POLL_WAIT = 25.0
POLL_MIN = 5.0
MAX_WAIT = 300.0
FULL_EVERY_S = 300.0
_STOPPED = object()
CHANGE_OF_OP = {
    "create": "joined",
    "join": "joined",
    "add": "added",
    "remove": "removed",
    "leave": "left",
    "role": "role",
    "transfer": "transfer",
    "rename": "renamed",
}
INVITE_OPS = frozenset({"invite", "revoke_invite", "join"})


def snapshot(c: Any) -> dict[str, dict]:
    """What the screens show of each lab, from the cache (no network)."""
    out: dict[str, dict] = {}
    for lab_id in c.lab_roster.labcache.labs():
        st = c.lab_roster.labcache.state(lab_id)
        if st is None or c.device.subject not in st.members:
            continue
        out[lab_id] = {
            "due": c.lab_keys.rotation_due(st),
            "epoch": c.lab_roster.labcache.epoch(lab_id),
            "invites": {k: (v["uses"], v["revoked"]) for k, v in st.invites.items()},
            "items": {
                v["item_id"]: (v["rev"], v["deleted"])
                for v, _ in c.lab_roster.labcache.items(lab_id, include_deleted=True)
            },
            "name": st.name,
            "seq": st.seq,
            "settings": c.lab_space.settings_rev(lab_id),
        }
    return out


def events(c: Any, before: dict[str, dict], after: dict[str, dict]) -> list[tuple[str, dict]]:
    """The lab events for the change from `before` to `after`."""
    out: list[tuple[str, dict]] = []
    for lab_id, old in before.items():
        if lab_id not in after:
            out.append(("lab.removed", {"lab": lab_id, "name": old["name"]}))
    for lab_id, new in after.items():
        old = before.get(lab_id)
        if old is None:
            out.append(("lab.members", {"change": "joined", "lab": lab_id}))
            continue
        invites = new["invites"] != old["invites"]
        if new["seq"] > old["seq"]:
            invites = _log_events(c, lab_id, old["seq"], out) or invites
        if invites:
            out.append(("lab.invites", {"lab": lab_id}))
        if (new["epoch"], new["due"]) != (old["epoch"], old["due"]):
            out.append(
                ("lab.key", {"epoch": new["epoch"], "lab": lab_id, "rotation_due": new["due"]})
            )
        if new["settings"] != old["settings"]:
            out.append(("lab.settings", {"lab": lab_id, "rev": new["settings"]}))
        out.extend(_space_events(lab_id, old["items"], new["items"]))
    return out


def _log_events(c: Any, lab_id: str, old_seq: int, out: list[tuple[str, dict]]) -> bool:
    """Add a `lab.members` event to `out` for each new roster entry after
    `old_seq`. Return True if a new entry changed the invites."""
    invites = False
    for e in c.lab_roster.labcache.entries(lab_id):
        if e["seq"] <= old_seq:
            continue
        change = CHANGE_OF_OP.get(e["op"])
        if change is not None:
            data = {"change": change, "lab": lab_id}
            if e.get("subject"):
                data["person"] = e["subject"]
            out.append(("lab.members", data))
        invites = invites or e["op"] in INVITE_OPS
    return invites


def _space_events(lab_id: str, old: dict, new: dict) -> list[tuple[str, dict]]:
    """A `lab.space` event for each item of the lab space that changed."""
    out = []
    for item_id, (rev, deleted) in sorted(new.items()):
        was = old.get(item_id)
        if was == (rev, deleted) or (was is None and deleted):
            continue
        change = "removed" if deleted else ("published" if was is None else "updated")
        out.append(("lab.space", {"change": change, "item": item_id, "lab": lab_id}))
    return out


class LabWatch:
    def __init__(
        self,
        service: UIService,
        publish: Callable[[str, dict], Any] | None = None,
        *,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self.service = service
        self._publish = publish
        self.clock = clock
        self.cursor: int | None = None
        self.failures = 0
        self.poll_min = POLL_MIN
        self._full_at = 0.0
        self._lock = threading.Lock()
        self._stopped = False
        self._conn: http.client.HTTPConnection | None = None

    def stop(self) -> None:
        """Abort any in-flight `/labs/changes` long-poll immediately."""
        with self._lock:
            self._stopped = True
            conn = self._conn
        if conn is not None:
            sock = conn.sock
            if sock is not None:
                with contextlib.suppress(OSError):
                    sock.shutdown(socket.SHUT_RDWR)
            with contextlib.suppress(OSError):
                conn.close()

    def wait(self) -> float:
        """The wait before the next turn: none after a good turn (the long
        poll waits), more after each failure."""
        if not self.failures:
            return 0.05
        return min(self.poll_min * (2 ** (self.failures - 1)), MAX_WAIT)

    def run(self) -> None:
        try:
            self.turn()
        except Exception:  # count the fault, then raise it again
            if self._stopped:
                return
            self.failures += 1
            raise
        self.failures = 0

    def _config(self, c: Any) -> tuple[float, float]:
        cfg = c.config.get("labs") if isinstance(c.config.get("labs"), dict) else {}
        wait = cfg.get("poll_wait", POLL_WAIT)
        low = cfg.get("poll_min", POLL_MIN)
        wait = float(wait) if isinstance(wait, int | float) else POLL_WAIT
        low = float(low) if isinstance(low, int | float) and low > 0 else POLL_MIN
        return max(0.0, min(wait, 25.0)), low

    def _get(self, c: Any, path: str, timeout: float) -> dict | None:
        """`GET path` with auth. For real HTTP, uses a closeable connection so
        `stop()` aborts the long-poll immediately instead of waiting for the
        server or a join timeout."""
        if getattr(self.service, "transport", None) is not None:
            return c.device.http.call("GET", path, auth=True)
        http_node = c.device.http
        if not http_node.token:
            raise NodeHTTPError(401, "no session; run `anagram login` to sign in again")
        parsed = urllib.parse.urlsplit(http_node.base_url)
        if parsed.scheme not in ("http", "https") or not parsed.hostname:
            raise ValueError("node URL must be http(s)")
        cls = (
            http.client.HTTPSConnection if parsed.scheme == "https" else http.client.HTTPConnection
        )
        conn = cls(parsed.hostname, parsed.port, timeout=timeout)
        with self._lock:
            if self._stopped:
                return None
            self._conn = conn
        try:
            conn.connect()
            with self._lock:
                if self._stopped:
                    return None
            full_path = parsed.path.rstrip("/") + path
            conn.request(
                "GET",
                full_path,
                headers={"Authorization": f"Bearer {http_node.token}"},
            )
            resp = conn.getresponse()
            raw = resp.read()
        except (OSError, http.client.HTTPException):
            if self._stopped:
                return None
            raise
        finally:
            with self._lock:
                if self._conn is conn:
                    self._conn = None
            with contextlib.suppress(OSError):
                conn.close()
        if resp.status >= 400:
            try:
                detail = json.loads(raw).get("detail", "")
            except (ValueError, AttributeError):
                detail = resp.reason
            raise NodeHTTPError(resp.status, str(detail))
        return json.loads(raw)

    def _poll(self, c: Any, wait: float) -> set[str] | None | object:
        """The labs with a change, None for "sync all", or `_STOPPED`."""
        full = self.cursor is None or self.clock() - self._full_at >= FULL_EVERY_S
        if self.cursor is None:
            head = self._head(c)
            if head is None:
                return _STOPPED
            self.cursor = head
            return None
        poll_wait = 0.0 if full else wait
        data = self._get(
            c,
            f"/labs/changes?after={self.cursor}&wait={poll_wait:g}",
            timeout=max(poll_wait + 30.0, 30.0),
        )
        if data is None:
            return _STOPPED
        self.cursor = max(self.cursor, int(data.get("next") or 0))
        if full:
            return None
        return {r["lab_id"] for r in data.get("changes") or [] if isinstance(r, dict)}

    def _head(self, c: Any) -> int | None:
        """The newest change now (the feed gives at most 500 rows a call)."""
        after = 0
        while True:
            data = self._get(c, f"/labs/changes?after={after}&wait=0", timeout=30.0)
            if data is None:
                return None
            nxt = int(data.get("next") or after)
            if len(data.get("changes") or []) < 500 or nxt <= after:
                return nxt
            after = nxt

    def turn(self) -> None:
        if self._stopped:
            return
        with self.service.open_client() as c:
            wait, self.poll_min = self._config(c)
            changed = self._poll(c, wait)
        if changed is _STOPPED or self._stopped:
            return
        with self.service.open_client(index=True) as (c, idx):
            before = snapshot(c)
            if changed is None:
                c.labs.lab_sync()
                self._full_at = self.clock()
            else:
                for lab_id in sorted(changed):
                    c.labs.lab_sync(lab_id)
            sync_lab_index(c.lab_context, idx, scan=changed is None or bool(changed))
            found = events(c, before, snapshot(c))
        if self._publish is not None:
            for type_, data in found:
                self._publish(type_, data)
