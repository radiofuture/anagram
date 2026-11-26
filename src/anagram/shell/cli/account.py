"""CLI commands for the account: sign-in, keys, devices, and recovery.

The `anagram` parser shows its commands in a fixed order, so this module has
three register functions; `anagram.shell.cli.main` calls each one time.

    anagram join INVITE_URL --name N [--address ADDR] [--kit-file PATH] ...
    anagram login [--orcid | --fake-orcid ID | --email ADDR | --no-browser] [--reset] ...
    anagram orcid link [--fake-orcid ID | --no-browser]
    anagram whoami | anagram logout
    anagram keys lookup PERSON | anagram keys monitor
    anagram device request | anagram device add REQUEST
    anagram recover KIT_FILE | anagram recover --guardians [--invite URL] [--fake-orcid ID]
    anagram findable on|off
    anagram guardians set PERSON... [--threshold K] | guardians requests | guardians approve ID
"""

from __future__ import annotations

import json
from pathlib import Path

from anagram.core.errors import ClientError
from anagram.shell.client import Client

KIT_FILE_HELP = "write the recovery kit to this file (outside the data directory)"


def _signin_options(args):
    """(method, browser, email code function) for `join`, `login`, and
    `orcid link`. With no ORCID or email option, the method is the main path:
    the invite (join) or the device key (login)."""
    from anagram.identity.api import (
        HeadlessBrowser,
        LoopbackBrowser,
        PasteBrowser,
        urllib_fetch,
    )

    browser = None
    if getattr(args, "fake_orcid", None):
        browser = HeadlessBrowser(urllib_fetch)
    elif getattr(args, "no_browser", False):
        browser = PasteBrowser()
    elif getattr(args, "orcid", False):
        browser = LoopbackBrowser()
    method = None
    if getattr(args, "email", None):
        method = "email"
    elif browser is not None:
        method = "orcid"
    # An invite to an email address asks for the code that the node sends.
    code_fn = lambda: input("Code from the email: ").strip()  # noqa: E731
    return method, browser, code_fn


def _kit_target(args) -> Path | None:
    """The path of `--kit-file`, checked before the sign-in starts."""
    from anagram.identity.api import kit_file_path

    given = getattr(args, "kit_file", None)
    return kit_file_path(args.home, given) if given else None


def _print_kit(args, r, target: Path | None) -> None:
    """Show the recovery code. Write the kit only to a path that the person
    gave: no kit file is put into the data directory."""
    from anagram.identity.api import write_kit_file

    print(f"Recovery code: {r.recovery_code}")
    if target is None:
        print("Recovery kit: not written. Keep the recovery code offline, or run the")
        print("command again with --kit-file PATH (a path outside the data directory).")
        return
    write_kit_file(args.home, target, r.kit_text)
    r.client.account.drop_pending_kit()
    print(f"Recovery kit: {target}  (print it, keep it offline, then delete the file)")


def cmd_join(args) -> int:
    from anagram.admission.api import join

    kit_target = _kit_target(args)
    method, browser, code_fn = _signin_options(args)
    if method is None and not args.name:
        raise ClientError("give your name with --name (as colleagues know it)")
    r = join(
        args.home,
        args.invite,
        browser=browser,
        login_hint=args.fake_orcid,
        email=args.email,
        email_code=code_fn,
        display_name=args.name,
        institution=args.institution,
        reset=args.reset,
        method=method or "invite",
        stated_email=args.address,
        open_home=Client.open,
    )
    print(f"Signed in as {r.subject} ({r.client.config['identity']['community']})")
    if r.client.account.orcid:
        print(f"ORCID iD: {r.client.account.orcid} (not public; the log shows only a commitment)")
    if r.status == "pending_device":
        print("You already have keys on another device. On that device, run:")
        print(f"  anagram device add {r.device_request}")
        print("Then run this `anagram join` command again here.")
        return 3
    print(f"Device key: {r.client.device.my_device()['ed25519']}")
    _print_kit(args, r, kit_target)
    return 0


def cmd_login(args) -> int:
    from anagram.identity.api import login

    kit_target = _kit_target(args)
    method, browser, code_fn = _signin_options(args)
    r = login(
        args.home,
        browser=browser,
        login_hint=args.fake_orcid,
        email=args.email,
        email_code=code_fn,
        reset=args.reset,
        method=method or "device",
        open_home=Client.open,
    )
    print(f"Signed in again as {r.subject} ({r.client.config['identity']['community']})")
    if r.status == "pending_device":
        print("This device is not approved yet. On a device that you use now, run:")
        print(f"  anagram device add {r.device_request}")
        print("Then run `anagram login` again here.")
        return 3
    if r.recovery_code:
        _print_kit(args, r, kit_target)
    return 0


def cmd_orcid_link(args) -> int:
    """Link an ORCID iD to the account (optional)."""
    _, browser, _ = _signin_options(args)
    from anagram.identity.api import LoopbackBrowser

    c = Client(args.home)
    try:
        orcid = c.account.link_orcid(browser or LoopbackBrowser(), login_hint=args.fake_orcid)
    finally:
        c.vault.close()
    print(f"ORCID iD linked: {orcid}. It shows on your matches and your proof certificate.")
    return 0


def cmd_whoami(args) -> int:
    print(json.dumps(Client(args.home).account.whoami(), indent=2, sort_keys=True))
    return 0


def cmd_logout(args) -> int:
    Client(args.home).account.logout()
    print("Signed out. Run `anagram login` to sign in again.")
    return 0


def cmd_keys_lookup(args) -> int:
    state = Client(args.home).directory.lookup(args.who)
    print(json.dumps({"devices": list(state.devices.values()), "subject": state.subject}, indent=2))
    return 0


def cmd_keys_monitor(args) -> int:
    alerts = Client(args.home).directory.monitor()
    for a in alerts:
        print(f"ALERT: {a}")
    if not alerts:
        print("No unexpected keys.")
    return 4 if alerts else 0


def cmd_device_request(args) -> int:
    print(Client(args.home).account.device_request())
    return 0


def cmd_device_add(args) -> int:
    entry = Client(args.home).account.add_device(args.request)
    print(f"Added device {entry['device']['ed25519']}")
    return 0


def cmd_recover(args) -> int:
    from anagram.identity.api import recover

    if args.guardians:
        return _recover_guardians(args)
    if not args.kit:
        raise ClientError("give a recovery kit file, or use --guardians")
    client = recover(args.home, Path(args.kit).read_text(), open_home=Client.open)
    print(
        f"Keys restored for {client.device.subject}. Device key: {client.device.my_device()['ed25519']}"
    )
    _print_restore(client)
    return 0


def _print_restore(client) -> None:
    r = client.personal.last_restore or {}
    if r.get("status") == "restored":
        snaps = ", ".join(f"{k}: {v}" for k, v in sorted(r["snapshots"].items()))
        print(f"Personal store: {r['pulled']} record(s) restored ({snaps}).")
    elif r:
        print(f"Personal store: {r.get('status')}.")


def _recover_guardians(args) -> int:
    from anagram.admission.api import node_of
    from anagram.identity.api import (
        HeadlessBrowser,
        finish_guardian_recovery,
        pending_recovery,
        start_guardian_recovery,
        urllib_fetch,
    )

    if pending_recovery(args.home) is None:
        browser = HeadlessBrowser(urllib_fetch) if args.fake_orcid else None
        node = {"node_key": args.node_key, "node_url": args.node_url}
        if args.invite:
            node = node_of(args.invite)
        rid = start_guardian_recovery(
            args.home,
            **node,
            browser=browser,
            login_hint=args.fake_orcid,
            email=args.email,
            email_code=(lambda: input("Code from the email: ").strip()) if args.email else None,
        )
        print(f"Recovery request: {rid}")
        print("Call each guardian. Ask them to check the request and run:")
        print(f"  anagram guardians approve {rid}")
        print("Then run `anagram recover --guardians` here again.")
        return 3
    client = finish_guardian_recovery(args.home, open_home=Client.open)
    print(
        f"Keys restored for {client.device.subject}. Device key: {client.device.my_device()['ed25519']}"
    )
    _print_restore(client)
    return 0


def cmd_findable(args) -> int:
    on = args.state == "on"
    Client(args.home).account.set_findable(on)
    if on:
        print("Findable: on. Members who know your email address or ORCID iD can find you.")
    else:
        print("Findable: off. Members find you only in the member list.")
    return 0


def cmd_guardians(args) -> int:
    c = Client(args.home)
    if args.guardians_command == "set":
        out = c.guardians.guardians_set(args.who, threshold=args.threshold)
        print(f"Guardians: {', '.join(out['guardians'])}. Any {out['threshold']} can help you.")
        return 0
    if args.guardians_command == "requests":
        for r in c.guardians.guardian_requests():
            dev = r["request"]["device"]["ed25519"]
            print(
                f"{r['request_id']}  {r['request']['subject']}  new device {dev[:16]}..."
                f"  check: {r['check']}"
            )
        return 0
    return _guardians_approve(c, args)


def _guardians_approve(c: Client, args) -> int:
    reqs = {r["request_id"]: r for r in c.guardians.guardian_requests()}
    r = reqs.get(args.request)
    if r is None:
        raise ClientError("no recovery request with this ID for which you are a guardian")
    if r["check"] != "ok":
        raise ClientError(r["check"])
    dev = r["request"]["device"]["ed25519"]
    print(f"Recovery request from {r['request']['subject']} for new device {dev}.")
    print("Approve only if you confirmed this with the person by another channel.")
    if not args.yes and input("Approve? [y/N] ").strip().lower() != "y":
        print("Not approved.")
        return 1
    c.guardians.guardian_approve(args.request)
    print("Approved. Your share is encrypted to the new device only.")
    return 0


def register(sub) -> None:
    """Add join, login, orcid, whoami, logout, keys, and device."""
    p = sub.add_parser("join", help="join a community from an invite link")
    p.add_argument("invite")
    p.add_argument("--name", help="your name, as colleagues know it")
    p.add_argument("--address", help="your email address; members can find you by it")
    p.add_argument("--orcid", action="store_true", help="join with ORCID (optional)")
    p.add_argument("--fake-orcid", help="ORCID iD for a node in fake ORCID mode (local dev)")
    p.add_argument("--email", help="join with an email code (optional)")
    p.add_argument("--no-browser", action="store_true", help="ORCID: paste the one-time code")
    p.add_argument("--institution", help="ROR ID of your institution")
    p.add_argument("--reset", action="store_true", help="replace all your old device keys")
    p.add_argument("--kit-file", metavar="PATH", help=KIT_FILE_HELP)
    p.set_defaults(func=cmd_join)

    p = sub.add_parser("login", help="sign in again (members; no invite needed)")
    p.add_argument("--orcid", action="store_true", help="sign in with ORCID")
    p.add_argument("--fake-orcid", help="ORCID iD for a node in fake ORCID mode (local dev)")
    p.add_argument("--email", help="sign in with an email code")
    p.add_argument("--no-browser", action="store_true", help="ORCID: paste the one-time code")
    p.add_argument("--reset", action="store_true", help="replace all your old device keys")
    p.add_argument("--kit-file", metavar="PATH", help=KIT_FILE_HELP)
    p.set_defaults(func=cmd_login)

    p = sub.add_parser("orcid", help="your ORCID iD (optional)")
    osub = p.add_subparsers(dest="orcid_command", required=True)
    s = osub.add_parser("link", help="link your ORCID iD")
    s.add_argument("--fake-orcid", help="ORCID iD for a node in fake ORCID mode (local dev)")
    s.add_argument("--no-browser", action="store_true", help="paste the one-time code")
    s.set_defaults(func=cmd_orcid_link)

    p = sub.add_parser("whoami", help="show your identity on the node")
    p.set_defaults(func=cmd_whoami)

    p = sub.add_parser("logout", help="end the session on the node")
    p.set_defaults(func=cmd_logout)

    p = sub.add_parser("keys", help="key directory")
    ksub = p.add_subparsers(dest="keys_command")
    s = ksub.add_parser("lookup", help="keys of a person, with log proofs")
    s.add_argument("who", help="ORCID iD or subject")
    s.set_defaults(func=cmd_keys_lookup)
    s = ksub.add_parser("monitor", help="check the log for unexpected keys for you")
    s.set_defaults(func=cmd_keys_monitor)

    p = sub.add_parser("device", help="add a second device")
    dsub = p.add_subparsers(dest="device_command")
    s = dsub.add_parser("request", help="print the request of this device")
    s.set_defaults(func=cmd_device_request)
    s = dsub.add_parser("add", help="approve a new device (run on an existing device)")
    s.add_argument("request")
    s.set_defaults(func=cmd_device_add)


def register_recover(sub) -> None:
    """Add recover."""
    p = sub.add_parser("recover", help="restore keys from a recovery kit or guardians")
    p.add_argument("kit", nargs="?")
    p.add_argument("--guardians", action="store_true", help="ask your recovery guardians")
    p.add_argument("--invite", help="any invite link of the community (node URL and key)")
    p.add_argument("--node-url")
    p.add_argument("--node-key", help="node key fingerprint")
    p.add_argument("--fake-orcid", help="ORCID iD for a node in fake ORCID mode (local dev)")
    p.add_argument("--email", help="sign in with email instead of ORCID")
    p.set_defaults(func=cmd_recover)


def register_guardians(sub) -> None:
    """Add findable and guardians."""
    p = sub.add_parser("findable", help="findable by email address or ORCID iD")
    p.add_argument("state", choices=["on", "off"])
    p.set_defaults(func=cmd_findable)

    p = sub.add_parser("guardians", help="recovery guardians (Shamir, k of n)")
    gsub = p.add_subparsers(dest="guardians_command")
    s = gsub.add_parser("set", help="choose guardians")
    s.add_argument("who", nargs="+", help="ORCID iDs")
    s.add_argument("--threshold", type=int, default=2)
    s.set_defaults(func=cmd_guardians)
    s = gsub.add_parser("requests", help="recovery requests where you are a guardian")
    s.set_defaults(func=cmd_guardians)
    s = gsub.add_parser("approve", help="approve a recovery request (explicit)")
    s.add_argument("request")
    s.add_argument("--yes", action="store_true", help="do not ask again")
    s.set_defaults(func=cmd_guardians)
