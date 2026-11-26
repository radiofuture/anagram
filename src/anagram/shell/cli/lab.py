"""`anagram lab ...`: the lab commands.

    anagram lab create NAME
    anagram lab list
    anagram lab show LAB
    anagram lab invite LAB [--role member|admin] [--uses N] [--days D]
    anagram lab revoke LAB INVITE_ID
    anagram lab join LINK                  (a node member; a new person uses `anagram join LINK`)
    anagram lab add LAB PERSON [--role member|admin]
    anagram lab remove LAB PERSON
    anagram lab leave LAB
    anagram lab role LAB PERSON ROLE
    anagram lab transfer LAB PERSON
    anagram lab rename LAB NAME
    anagram lab rotate LAB
    anagram lab sync                       roster, keys, lab space, then the local index
    anagram lab publish LAB SOURCE KEY     put one indexed item into the lab space
    anagram lab items LAB
    anagram lab use LAB [--institution ROR]

LAB is a lab ID or the exact name of a lab in the local cache. PERSON is a
person ID or the ORCID iD of a findable member.
"""

from __future__ import annotations

import argparse

from anagram.network.api import (
    LabError,
    publish_index_item,
    sync_lab_index,
)
from anagram.shell.client import Client


def _lab(c: Client, value: str) -> str:
    """A lab ID, or the ID of the one cached lab with this exact name."""
    if value.startswith("lab-"):
        return value
    found = [x["lab_id"] for x in c.labs.lab_list() if x["name"] == value]
    if len(found) != 1:
        raise LabError("No lab with this name, or more than one. Use the lab ID.")
    return found[0]


def _members(roles: dict[str, str]) -> str:
    return ", ".join(f"{pid} ({role})" for pid, role in sorted(roles.items()))


def cmd_lab_create(args) -> int:
    lab = Client(args.home).labs.lab_create(args.name)
    print(f"Lab {lab['lab_id']}: {lab['name']}")
    return 0


def cmd_lab_list(args) -> int:
    rows = Client(args.home).labs.lab_list()
    if not rows:
        print("You are in no lab. Run `anagram lab sync` after you join one.")
    for x in rows:
        due = "  (key change due)" if x["rotation_due"] else ""
        print(f"{x['lab_id']}  {x['name']}  {x['role']}  {x['members']} members{due}")
    return 0


def cmd_lab_show(args) -> int:
    c = Client(args.home)
    lab_id = _lab(c, args.lab)
    state = c.lab_roster.lab_state(lab_id)
    print(f"Lab {lab_id}: {state.name}")
    print(f"Your role: {state.members.get(c.device.subject)}")
    print(f"Members: {_members(state.members)}")
    print(f"Key epoch: {c.lab_roster.labcache.epoch(lab_id)}")
    for iid in state.open_invites(c.device.now()):
        inv = state.invites[iid]
        auth = inv["auth"]
        print(
            f"Invite {iid}: {auth['role']}, {inv['uses']} of {auth['max_uses']} used,"
            f" ends {auth['expires_at']}"
        )
    return 0


def cmd_lab_invite(args) -> int:
    c = Client(args.home)
    out = c.admission.lab_invite(
        _lab(c, args.lab), role=args.role, max_uses=args.uses, expires_days=args.days
    )
    print(out["url"])
    print(f"Invite {out['invite_id']} ends {out['expires_at']}.")
    print("Each person with this link can join and read the lab space.")
    return 0


def cmd_lab_revoke(args) -> int:
    c = Client(args.home)
    c.admission.lab_revoke_invite(_lab(c, args.lab), args.invite_id)
    print("The invite link does not work now.")
    return 0


def cmd_lab_join(args) -> int:
    out = Client(args.home).admission.lab_join(args.link)
    print(f"You are in the lab {out['name']} ({out['lab_id']}) as {out['role']}.")
    return 0


def cmd_lab_add(args) -> int:
    c = Client(args.home)
    lab = c.labs.lab_add(_lab(c, args.lab_id), args.who, role=args.role)
    print(f"Lab {lab['lab_id']} members: {', '.join(lab['members'])}")
    return 0


def _view_cmd(fn, done: str):
    def run(args) -> int:
        c = Client(args.home)
        view = fn(c, args)
        print(done)
        print(f"Members: {_members(view['roles'])}")
        return 0

    return run


cmd_lab_remove = _view_cmd(
    lambda c, a: c.labs.lab_remove(_lab(c, a.lab), a.who),
    "The person is not in the lab now. The lab key changed.",
)
cmd_lab_role = _view_cmd(
    lambda c, a: c.labs.lab_set_role(_lab(c, a.lab), a.who, a.role), "The role changed."
)
cmd_lab_transfer = _view_cmd(
    lambda c, a: c.labs.lab_transfer(_lab(c, a.lab), a.who),
    "The PI role moved. You are an admin now.",
)
cmd_lab_rename = _view_cmd(
    lambda c, a: c.labs.lab_rename(_lab(c, a.lab), a.name), "The lab name changed."
)


def cmd_lab_leave(args) -> int:
    c = Client(args.home)
    lab_id = _lab(c, args.lab)
    c.labs.lab_leave(lab_id)
    _sync_index(c)
    print("You left the lab. Your private items stay with you.")
    return 0


def cmd_lab_rotate(args) -> int:
    c = Client(args.home)
    n = c.lab_keys.lab_rotate(_lab(c, args.lab))
    print(f"The lab key changed (epoch {n}).")
    return 0


def _sync_index(c: Client) -> dict:
    from anagram.local.api import LocalIndex

    idx = LocalIndex.for_client(c)
    try:
        return sync_lab_index(c.lab_context, idx)
    finally:
        idx.close()


def cmd_lab_sync(args) -> int:
    c = Client(args.home)
    out = c.labs.lab_sync()
    for lab_id, row in sorted(out["labs"].items()):
        if row.get("removed"):
            print(f"{lab_id}: you are not in this lab now")
            continue
        changed = " (new key)" if row["rotated"] else ""
        print(f"{lab_id}: {row['items']} new items, key epoch {row['epoch']}{changed}")
    got = _sync_index(c)
    print(
        f"Index: {len(got['sources'])} lab sources, {got['published']} items published,"
        f" {got['withdrawn']} withdrawn"
    )
    return 0


def cmd_lab_publish(args) -> int:
    from anagram.local.api import LocalIndex

    c = Client(args.home)
    lab_id = _lab(c, args.lab)
    idx = LocalIndex.for_client(c)
    try:
        item_id = publish_index_item(c.lab_context, idx, lab_id, args.source, args.key)
    finally:
        idx.close()
    print(f"In the lab space: {item_id}")
    return 0


def cmd_lab_items(args) -> int:
    c = Client(args.home)
    lab_id = _lab(c, args.lab)
    rows = sorted(c.lab_space.lab_items(lab_id), key=lambda v: (v["published_at"], v["item_id"]))
    if not rows:
        print("The lab space has no items. Run `anagram lab sync` to get new ones.")
    for v in rows:
        kind = v["type"] or v["kind"]
        print(f"{v['item_id']}  {v['published_at']}  {kind}  {v['title']}  ({v['author']})")
    return 0


def cmd_lab_use(args) -> int:
    """Put a lab (and optionally the institution ROR ID) in my identity record."""
    c = Client(args.home)
    old = c.account.whoami().get("identity") or {}
    rec = c.account.set_identity(
        old.get("display_name") or c.device.subject,
        institution=args.institution or old.get("institution"),
        lab_id=args.lab_id,
    )
    print(f"Identity: {rec['display_name']}, lab {rec['lab_id']}, institution {rec['institution']}")
    return 0


def register(sub: argparse._SubParsersAction) -> None:
    p = sub.add_parser("lab", help="labs")
    lsub = p.add_subparsers(dest="lab_command")

    def cmd(name: str, fn, text: str, *pos: str) -> argparse.ArgumentParser:
        s = lsub.add_parser(name, help=text)
        for a in pos:
            s.add_argument(a)
        s.set_defaults(func=fn)
        return s

    cmd("create", cmd_lab_create, "create a lab (you are the PI)", "name")
    cmd("list", cmd_lab_list, "your labs (local cache)")
    cmd("show", cmd_lab_show, "members, roles, key, open invites", "lab")
    s = cmd("invite", cmd_lab_invite, "make an invite link (PI or admin)", "lab")
    s.add_argument("--role", choices=["member", "admin"], default="member")
    s.add_argument("--uses", type=int, default=1, help="number of people (1 to 25)")
    s.add_argument("--days", type=float, default=7, help="days until the link ends")
    cmd("revoke", cmd_lab_revoke, "stop an invite link", "lab", "invite_id")
    cmd("join", cmd_lab_join, "join a lab with an invite link (node members)", "link")
    s = cmd("add", cmd_lab_add, "add a node member to your lab", "lab_id", "who")
    s.add_argument("--role", choices=["member", "admin"], default="member")
    cmd("remove", cmd_lab_remove, "remove a member (the lab key changes)", "lab", "who")
    cmd("leave", cmd_lab_leave, "leave a lab", "lab")
    s = cmd("role", cmd_lab_role, "change the role of a member (PI)", "lab", "who")
    s.add_argument("role", choices=["member", "admin"])
    cmd("transfer", cmd_lab_transfer, "give the PI role to a member", "lab", "who")
    cmd("rename", cmd_lab_rename, "rename the lab", "lab", "name")
    cmd("rotate", cmd_lab_rotate, "change the lab key now (PI or admin)", "lab")
    cmd("sync", cmd_lab_sync, "get lab changes and update the local index")
    cmd(
        "publish",
        cmd_lab_publish,
        "put one indexed item into the lab space",
        "lab",
        "source",
        "key",
    )
    cmd("items", cmd_lab_items, "items of the lab space (local cache)", "lab")
    s = cmd("use", cmd_lab_use, "put this lab in your identity record (for matching)", "lab_id")
    s.add_argument("--institution", help="ROR ID of your institution")
