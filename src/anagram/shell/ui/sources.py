"""Sources for the local UI (layer L2): kinds, add, list, change, pause,
resume, sync, refresh, removal, the choices of a connected source, and the
folder picker. It is the part `UIService.sources`; `shell/ui/routers/sources.py`
has the routes. Connected accounts are the part `UIService.connections`
(`connections.py`); the source settings of a lab are `UIService.lab_sources`
(`lab_sources.py`); the kinds and the sentences are in `source_kinds.py`.

Rules:

- A source row holds no token, no stream ID, and no converter text. The row
  has the keys that the Sources screen reads.
- Events go to `source_state.publisher(store)`, which appends rows to the
  table `source_event`. This class does not call the UI event bus; the event
  bridge moves the rows to the one event stream.
- The state of a source (status, pause, space, fault) is in `source_state`.
  This class adds the sentence for the person to a fault.
- A source whose items are the work of other people (`own = False`, the lab
  space source) is shown, but it cannot be changed, paused, or removed here.
"""

from __future__ import annotations

import logging
import re
from dataclasses import replace
from pathlib import Path, PurePosixPath
from typing import TYPE_CHECKING

from anagram.core.errors import ClientError
from anagram.core.timefmt import iso_seconds
from anagram.local.api import (
    KIND_SCOPES,
    PRIVATE,
    PROVIDERS,
    SOURCES,
    VAULT_DIR,
    ConnectorError,
    OrcidWorksConnector,
    SourceContext,
    SourceFault,
    Suggestion,
    client_resolver,
    connector_from_config,
    describe_suggestions,
    discover,
    helper_running,
    kind_label,
    remove_source,
    source_label,
    source_state,
)
from anagram.local.api import (
    STATUS_KEY as INDEXER_STATUS_KEY,
)
from anagram.local.api import (
    is_raw as is_raw_label,
)
from anagram.local.api import (
    shown as shown_label,
)
from anagram.network.api import (
    lab_space_hook,
)
from anagram.shell.ui.errors import UIError
from anagram.shell.ui.source_kinds import (
    FAULT_TEXT,
    FLOW_TEXT,
    KINDS,
    LAB,
    PROVIDER_NAMES,
    SPACE_REFUSED,
    KindInfo,
    credentials,
    error,
    kind_info,
)

if TYPE_CHECKING:
    from anagram.local.api import LocalIndex
    from anagram.shell.ui.service import UIService

log = logging.getLogger("anagram.shell.ui")

CHECKPOINT_INTERVAL = 3600  # at most one checkpoint per source per hour

LABEL_MAX = 120
SKIPPED_IN_LIST = 50
_SID = re.compile(r"^[0-9a-f]{32}$")


def _identity(cfg: dict) -> tuple:
    """What makes two configs the same source (the kind and its place)."""
    place = cfg.get("root") or cfg.get("repo") or cfg.get("path") or cfg.get("orcid")
    return (cfg.get("kind"), place, cfg.get("account"))


def default_label(s: Suggestion) -> str:
    """A name for a new source with no full path in it (experience rule
    9): the last part of the path, for example "Lab notes". A
    connected source has the label of `_cloud` (kind and account)."""
    if s.config.get("account"):
        return s.label
    return source_label(s.config)


def vault_rules(root: Path, found: list[Suggestion]) -> list[Suggestion]:
    """An Obsidian vault is its own source. If the folder is a vault, the
    folder suggestion with the same root goes. If vaults are inside the
    folder, the folder source excludes them."""
    vaults = [Path(s.config["root"]) for s in found if s.kind == "obsidian"]
    out = []
    for s in found:
        if s.kind == "folder" and Path(s.config["root"]) == root:
            if root in vaults:
                continue
            inside = sorted(v.relative_to(root).as_posix() for v in vaults)
            if inside:
                s = replace(s, config={**s.config, "exclude": inside})
        out.append(s)
    return out


class SourcesUI:
    def __init__(self, ui: UIService) -> None:
        self.ui = ui
        self.last_refresh: dict | None = None

    def _now(self) -> float:
        return self.ui.clock()

    # --------------------------------------------------------------- kinds

    def kinds(self) -> dict:
        with self.ui.session() as c:
            orcid = bool(c.account.orcid)
            resolve = client_resolver(c.lab_context, c.home)
            clients = {p: resolve(p) is not None for p in PROVIDERS}
            labs = self._lab_choices(c)
        out = []
        for info in KINDS.values():
            reason = None
            if info.kind == "orcid_works" and not orcid:
                reason = "This needs an ORCID sign-in."
            if info.auth == "oauth" and not clients.get(info.provider or ""):
                name = PROVIDER_NAMES.get(info.provider or "", "the service")
                if labs:
                    reason = f"Not set up for this lab. Ask your lab admin to add a {name} client."
                else:
                    reason = f"Start or join a lab to connect {name}."
            out.append(
                {
                    "auth": info.auth,
                    "available": reason is None,
                    "choose": info.choose,
                    "kind": info.kind,
                    "label": kind_label(info.kind),
                    "provider": info.provider,
                    "spaces": list(info.spaces),
                    "unavailable_reason": reason,
                    **self._spaces_of(info, labs),
                }
            )
        return {"kinds": out}

    # ---------------------------------------------------------------- rows

    def _fault(self, state: source_state.SourceState, kind: str) -> dict | None:
        fault = state.fault
        if fault is None:
            return None
        info = KINDS.get(kind)
        if fault["code"] == "not_found":
            message = info.missing if info is not None else "This source is not there."
        else:
            provider = PROVIDER_NAMES.get(info.provider if info else None, "the service")
            message = FAULT_TEXT.get(fault["code"], FAULT_TEXT["unknown"]).format(provider=provider)
        return {**fault, "message": message}

    def _row(self, idx: LocalIndex, sid: str, src: dict, *, full: bool = False) -> dict:
        kind = src["config"]["kind"]
        state = source_state.get(idx.store, sid, self._now())
        progress = idx.jobs.progress(sid)
        prefs = src["prefs"]
        fault = self._fault(state, kind)
        skipped = progress["skipped"]
        row = {
            "account": source_state.account_view(idx.store, state.account_id),
            "assistant": bool(prefs.get("assistant", True)),
            "checkpoints": src["seq"],
            "converting": progress["converting"],
            "error": fault["message"] if fault else None,
            "fault": fault,
            "id": sid,
            "indexed": progress["indexed"],
            "items": progress["total"],
            "kind": kind,
            "kind_label": idx.kinds.label(kind),
            "label": shown_label(idx.store, src["label"], src["config"]),
            "last_change_at": src["last_change_at"],
            "last_checkpoint_at": src["last_checkpoint_at"],
            "last_sync_at": src["last_scan_at"],
            "own": idx.is_own(sid),
            "paused": state.paused,
            "phase": state.phase,
            "progress": {
                "at": state.at,
                "done": state.done if state.done is not None else progress["indexed"],
                "skipped": state.skipped,
                "total": state.total if state.total is not None else progress["total"],
            },
            "skipped": skipped if full else skipped[:SKIPPED_IN_LIST],
            "skipped_count": len(skipped),
            "space": state.space,
            "status": state.status,
            "waiting": len(src["pending"]),
        }
        if full:
            cfg = src["config"]
            include = {"exclude": list(cfg.get("exclude", []))} if "root" in cfg else None
            row.update(filter=cfg.get("filter"), include=cfg.get("include", include))
        return row

    def _source(self, idx: LocalIndex, sid: str) -> dict:
        if not isinstance(sid, str) or not _SID.match(sid):
            raise error(404, "not_found", "This source is not there.")
        try:
            return idx.source(sid)
        except KeyError:
            raise error(404, "not_found", "This source is not there.") from None

    def _editable(self, idx: LocalIndex, sid: str) -> dict:
        """The source, if the member can change it here."""
        src = self._source(idx, sid)
        if not idx.is_own(sid):
            raise error(403, "lab_source", "Your lab controls this source.")
        state = source_state.read(idx.store, sid)
        if state is not None and state.stored_status == source_state.REMOVING:
            raise error(409, "removing", "This source is being removed.")
        return src

    def _publish(self, idx: LocalIndex):
        return source_state.publisher(idx.store, self.ui.clock)

    def list(self) -> dict:
        out = []
        with self.ui.session(index=True) as (_, idx):
            status = idx.get_status(INDEXER_STATUS_KEY)
            for sid, src in sorted(idx.sources().items(), key=lambda kv: kv[1]["created_at"]):
                out.append(self._row(idx, sid, src))
        helper = None
        if helper_running(status, self._now()):
            helper = {
                "errors": status.get("errors", [])[-5:],
                "last_cycle_at": status.get("last_cycle_at"),
                "next_poll_at": status.get("next_poll_at"),
            }
        return {"helper": helper, "last_refresh": self.last_refresh, "sources": out}

    def helper_status(self) -> dict | None:
        """The status of the background helper (`anagram indexer`), if one runs."""
        with self.ui.session(index=True) as (_, idx):
            status = idx.get_status(INDEXER_STATUS_KEY)
        return status if helper_running(status, self._now()) else None

    @staticmethod
    def browse(path: str | None) -> dict:
        """Folders on this computer, for the folder picker. Names only."""
        p = Path(path).expanduser() if path else Path.home()
        if not p.is_dir():
            raise UIError(400, "This folder does not exist.")
        p = p.resolve()
        dirs = []
        try:
            for child in sorted(p.iterdir(), key=lambda x: x.name.lower()):
                if child.name.startswith(".") or not child.is_dir():
                    continue
                dirs.append({"name": child.name, "path": str(child)})
        except PermissionError as exc:
            raise UIError(403, "Anagram may not read this folder.") from exc
        return {
            "dirs": dirs[:500],
            "is_git": (p / ".git").exists(),
            "is_obsidian": (p / VAULT_DIR).is_dir(),
            "parent": str(p.parent) if p.parent != p else None,
            "path": str(p),
        }

    def get(self, sid: str) -> dict:
        with self.ui.session(index=True) as (_, idx):
            return self._row(idx, sid, self._source(idx, sid), full=True)

    # ---------------------------------------------------------------- space

    def _policy(self, client, lab_id: str):
        """The lab policy (`lab_space.lab_policy`), or None for a lab that
        has no policy on this computer: the person is not in it, left it, or
        the lab cache does not have it yet (`ClientError`)."""
        try:
            return client.lab_space.lab_policy(lab_id)
        except ClientError:
            return None

    def _check_space(self, client, info: KindInfo, space: object) -> str:
        """A space value that this kind can have. A private source is never
        refused. A lab space needs the lab policy, and the policy
        must permit the kind (`LabPolicy.allows_source`)."""
        try:
            space = source_state.check_space(space)
        except source_state.SourceStateError:
            raise error(400, "bad_space", "Choose Private or one of your labs.") from None
        if space == PRIVATE:
            return space
        if LAB not in info.spaces:
            raise error(400, "space_refused", "This kind of source stays private.")
        policy = self._policy(client, space.removeprefix("lab:"))
        if policy is None:
            raise error(409, "space_unavailable", "The lab space is not ready on this computer.")
        if not policy.allows_source(info.kind):
            raise error(403, "space_refused", SPACE_REFUSED)
        return space

    def _lab_choices(self, client) -> list[tuple[dict, object]]:
        """Each lab of the person with its policy (labs with no policy on
        this computer are left out), in the order of `lab_list()`."""
        try:
            labs = client.labs.lab_list()
        except ClientError:
            return []
        out = []
        for lab in labs:
            policy = self._policy(client, lab["lab_id"])
            if policy is not None:
                out.append((lab, policy))
        return out

    def _spaces_of(self, info: KindInfo, labs: list[tuple[dict, object]]) -> dict:
        """The lab choices of one kind and the default space of the setup
        screen. A lab that refuses the kind is not a choice; the reason is
        one sentence. The default is the first lab whose `lab_default()` is
        `lab` and that permits the kind; Gmail is always private."""
        if LAB not in info.spaces:
            return {"default_space": PRIVATE, "labs": [], "lab_refused": None}
        choices, refused, default = [], False, PRIVATE
        for lab, policy in labs:
            if not policy.allows_source(info.kind):
                refused = True
                continue
            space = f"lab:{lab['lab_id']}"
            choices.append({"name": lab.get("name") or "Lab", "space": space})
            if default == PRIVATE and policy.lab_default() == LAB:
                default = space
        return {
            "default_space": default,
            "labs": choices,
            "lab_refused": SPACE_REFUSED if refused and not choices else None,
        }

    # ------------------------------------------------------------------ add

    def _found(self, client, info: KindInfo, path: object) -> list[Suggestion]:
        """The sources that a request to add one kind gives. A folder also
        gives the Git repositories, Zotero exports, and vaults in it."""
        if info.kind == "orcid_works":
            if not client.account.orcid:
                raise error(400, "no_orcid", "This needs an ORCID sign-in.")
            conn = OrcidWorksConnector(client.account.orcid)
            return [Suggestion(conn.kind, "My ORCID works", conn.config())]
        if not isinstance(path, str) or not path.strip():
            raise error(400, "no_path", "Choose a folder that exists.")
        p = Path(path).expanduser()
        if info.kind == "folder":
            if not p.is_dir():
                raise error(400, "no_path", "Choose a folder that exists.")
            found = discover(p, ["folder", "obsidian", "git", "zotero_file"])
            return vault_rules(p.resolve(), found)
        if info.kind == "obsidian":
            if not (p / VAULT_DIR).is_dir():
                raise error(400, "no_vault", "This folder is not an Obsidian vault.")
            return [s for s in discover(p, ["obsidian"]) if Path(s.config["root"]) == p.resolve()]
        if info.kind == "git":
            if not (p / ".git").exists():
                raise error(400, "no_repo", "This folder is not a Git repository.")
            return [s for s in discover(p, ["git"]) if Path(s.config["repo"]) == p.resolve()]
        if info.kind == "zotero_file":
            if not p.is_file():
                raise error(400, "no_path", "Choose the exported Zotero file (CSL JSON).")
            return discover(p, ["zotero_file"])
        raise error(400, "unknown_kind", "Unknown source type.")

    def _cloud_cfg(self, cfg: dict) -> dict:
        """The clean config of a connected source, or 400."""
        try:
            return connector_from_config(cfg).config()
        except (ConnectorError, KeyError, TypeError, ValueError):
            raise error(400, "bad_include", "Choose what to include.") from None

    def _account(self, idx: LocalIndex, info: KindInfo, account_id: object):
        """The account of a connected source. It must have the scopes of the
        kind (a sign-in for another kind adds them)."""
        acct = credentials(idx).account(account_id) if isinstance(account_id, str) else None
        if acct is None or acct.provider != info.provider:
            raise error(404, "no_account", "This account is not there.")
        if acct.status != "ok":
            raise error(
                409,
                "auth_expired",
                FAULT_TEXT["auth_expired"].format(
                    provider=PROVIDER_NAMES.get(acct.provider, "the service")
                ),
            )
        need = set(KIND_SCOPES.get(info.kind, ("", ()))[1])
        if not need <= set(acct.scopes):
            raise error(409, "scope_missing", FLOW_TEXT["scope_missing"])
        return acct

    def _cloud(self, idx: LocalIndex, info: KindInfo, body: dict) -> Suggestion:
        """The source that `{"kind", "account", "include"?, "filter"?}` gives."""
        acct = self._account(idx, info, body.get("account"))
        cfg = {"account": acct.id, "kind": info.kind}
        if info.auth == "api_key":
            cfg["user_id"] = acct.external_id  # Zotero: the library of the key
        for key in ("include", "filter"):
            if body.get(key) is not None:
                cfg[key] = body[key]
        cfg = self._cloud_cfg(cfg)
        return Suggestion(info.kind, source_label(cfg, acct.label), cfg)

    def _source_error(self, exc: SourceFault, info: KindInfo) -> UIError:
        provider = PROVIDER_NAMES.get(info.provider or "", "the service")
        if exc.code == "auth_expired":
            return error(409, "auth_expired", FAULT_TEXT["auth_expired"].format(provider=provider))
        if exc.code == "offline":
            return error(503, "offline", FAULT_TEXT["offline"])
        return error(502, exc.code, FAULT_TEXT["unknown"])

    def choices(self, account_id: str, kind: object, parent: str | None = None) -> dict:
        """What the person can include: Drive folders, Gmail labels, Notion
        pages. Read from the provider with the account of the member."""
        info = kind_info(kind)
        if info.auth == "none":
            raise error(400, "unknown_kind", "Unknown source type.")
        with self.ui.session(index=True) as (_, idx):
            acct = self._account(idx, info, account_id)
            cls = SOURCES.get(info.kind)
            ctx = SourceContext(http=idx.http, credentials=credentials(idx))
            try:
                return cls.choices(ctx, acct, parent)
            except SourceFault as exc:
                raise self._source_error(exc, info) from None

    def preview(self, body: dict) -> dict:
        """`{"estimate", "of"}`: about how many items the choice gives."""
        info = kind_info(body.get("kind"))
        if info.auth == "none":
            raise error(400, "unknown_kind", "Unknown source type.")
        with self.ui.session(index=True) as (_, idx):
            cfg = self._cloud(idx, info, body).config
            ctx = SourceContext(http=idx.http, credentials=credentials(idx))
            try:
                return SOURCES.get(info.kind).preview(ctx, cfg)
            except SourceFault as exc:
                raise self._source_error(exc, info) from None

    def add(self, body: dict, *, refresh: bool = True) -> dict:
        """Add a source from `{"kind", "path"?, "space"?, "label"?}`. A source
        that exists is not added again."""
        info = kind_info(body.get("kind"))
        label = self._label(body["label"]) if body.get("label") is not None else None
        added: list[str] = []
        with self.ui.session(index=True) as (c, idx):
            space = self._check_space(c, info, body.get("space", PRIVATE))
            if info.auth == "none":
                found = self._found(c, info, body.get("path"))
            else:
                found = [self._cloud(idx, info, body)]
            have = {_identity(src["config"]) for src in idx.sources().values()}
            publish = self._publish(idx)
            for s in found:
                if _identity(s.config) in have:
                    continue
                sid = idx.add_source(connector_from_config(s.config), label=default_label(s))
                source_state.ensure(
                    idx.store, sid, self._now(), space=space, account_id=s.config.get("account")
                )
                added.append(sid)
            if label is not None and len(added) == 1:
                idx.set_source_label(added[0], label)
            for sid in added:
                publish("source.added", {"source": self._row(idx, sid, idx.source(sid))})
        out = {"added": len(added), "found": describe_suggestions(found), "sources": added}
        if refresh:
            out["refresh"] = self.refresh(added)
        return out

    # -------------------------------------------------------------- refresh

    def refresh(self, sids: list[str] | None = None) -> dict:
        """Read the sources again. Evidence of new items is pending at once. A
        source gets a checkpoint when one is due (`CHECKPOINT_INTERVAL`; the
        first one is always due). Conversion runs here only when no background
        helper runs. A fault of a source goes into its state, not into the
        answer."""
        helper = self.helper_status() is not None
        with self.ui.session(index=True) as (c, idx):
            report = idx.scan(sids, process=False)
            targets = sids if sids is not None else sorted(idx.sources())
            stamped = 0
            for sid in targets:
                if idx.streams.checkpoint_due(sid, CHECKPOINT_INTERVAL):
                    idx.streams.checkpoint(c, sid)
                    stamped += 1
            if not helper:
                done = idx.jobs.run()
                for msg in done.errors:
                    log.warning("index job: %s", msg)
                for sid in targets:
                    try:
                        idx.scanner.after_scan(sid)  # for example the links of a vault
                    except Exception as exc:  # one source must not stop the rest
                        log.warning("work after the scan failed: %s", type(exc).__name__)
            if stamped:
                # The checkpoint salts are in the index: send a snapshot.
                c.personal.auto_sync()
        self.last_refresh = {
            "at": iso_seconds(self.ui.clock()),
            "changed": len(report.changed),
            "new": len(report.new),
            "stamped": stamped,
        }
        return self.last_refresh

    # --------------------------------------------------------------- change

    def _label(self, value: object) -> str:
        if not isinstance(value, str) or not value.strip() or len(value.strip()) > LABEL_MAX:
            raise error(400, "bad_label", "Give a name of 1 to 120 characters.")
        if is_raw_label(value.strip()):
            raise error(400, "bad_label", "Give a name, not a place on the disk.")
        return value.strip()

    def _flag(self, body: dict, name: str) -> bool | None:
        if name not in body:
            return None
        if not isinstance(body[name], bool):
            raise error(400, "bad_value", "This setting is on or off.")
        return body[name]

    def _include(self, cfg: dict, include: object) -> dict:
        """The new config of a folder or a vault for `{"exclude": [...]}`."""
        folders = include.get("exclude") if isinstance(include, dict) else None
        if "root" not in cfg or not isinstance(folders, list):
            raise error(400, "no_include", "This source has no choice of what to include.")
        clean = []
        for f in folders:
            path = PurePosixPath(f) if isinstance(f, str) else None
            if path is None or path.is_absolute() or ".." in path.parts or not path.parts:
                raise error(400, "bad_include", "Choose folders inside this source.")
            clean.append(path.as_posix())
        return connector_from_config({**cfg, "exclude": clean}).config()

    def patch(self, sid: str, body: dict) -> dict:
        """Change `label`, `include`, `space`, `assistant`.
        All values are checked before the first change is stored."""
        again = False
        with self.ui.session(index=True) as (c, idx):
            src = self._editable(idx, sid)
            cfg = src["config"]
            info = KINDS.get(cfg["kind"]) or KindInfo(cfg["kind"])
            label = self._label(body["label"]) if "label" in body else None
            assistant = self._flag(body, "assistant")
            space = self._check_space(c, info, body["space"]) if "space" in body else None
            cloud = info.auth != "none"
            if cloud and ("include" in body or "filter" in body):
                new_cfg = self._cloud_cfg(
                    {**cfg, **{k: body[k] for k in ("include", "filter") if k in body}}
                )
            else:
                if body.get("filter") is not None:
                    raise error(400, "no_filter", "This source has no filter.")
                new_cfg = self._include(cfg, body["include"]) if "include" in body else None
            if label is not None:
                idx.set_source_label(sid, label)
            if assistant is not None:
                idx.set_source_prefs(sid, assistant=assistant)
            if new_cfg is not None and new_cfg != cfg:
                idx.set_source_config(sid, new_cfg)
                if cloud:
                    # The source reads the new selection again and deletes
                    # each item that is no longer in it (a reconcile).
                    source_state.set_cursor(idx.store, sid, {"reset": True}, now=self._now())
                again = True
            if space is not None:
                try:
                    # The lab space hook publishes into or withdraws from the lab
                    # space now; it needs this client and index.
                    source_state.set_space(
                        idx.store,
                        sid,
                        space,
                        now=self._now(),
                        publish=self._publish(idx),
                        hooks=(lab_space_hook(c.lab_context, idx),),
                    )
                except source_state.SpaceHookError:
                    raise error(
                        502,
                        "space_pending",
                        "The space is changed. Anagram could not update the lab space now.",
                    ) from None
        if again:  # a narrower choice removes its items now
            self.refresh([sid])
        return self.get(sid)

    def pause(self, sid: str) -> dict:
        with self.ui.session(index=True) as (_, idx):
            self._editable(idx, sid)
            source_state.pause(idx.store, sid, now=self._now(), publish=self._publish(idx))
        return self.get(sid)

    def resume(self, sid: str) -> dict:
        with self.ui.session(index=True) as (_, idx):
            self._editable(idx, sid)
            source_state.resume(idx.store, sid, now=self._now(), publish=self._publish(idx))
        return self.get(sid)

    def sync(self, sid: str) -> dict:
        """Read one source now. The person acted, so a fault that waits is
        cleared first."""
        with self.ui.session(index=True) as (_, idx):
            self._editable(idx, sid)
            if source_state.get(idx.store, sid, self._now()).paused:
                raise error(409, "paused", "Resume this source first.")
            source_state.clear_fault(idx.store, sid, now=self._now(), publish=self._publish(idx))
        self.refresh([sid])
        return self.get(sid)

    # --------------------------------------------------------------- remove

    def remove(self, sid: str, *, delete_data: bool = True) -> dict:
        """Remove a source and delete what Anagram read from it. Items that a
        timestamped finding uses stay as proof, with no text."""
        if delete_data is not True:
            raise error(400, "keep_data", "Anagram removes a source with its data.")
        with self.ui.session(index=True) as (_, idx):
            self._editable(idx, sid)
            publish = self._publish(idx)
            out = remove_source(idx, sid, publish=publish)
        return {
            "account_revoked": out["account_revoked"],
            "kept_for_findings": out["kept_for_findings"],
            "removed_items": out["removed_items"],
        }
