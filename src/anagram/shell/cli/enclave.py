"""CLI of the matching enclave processes (`simulated` profile, development).

    anagram enclave devnet init --dir DIR --network NET --origin ORIGIN [--keys DIR]
    anagram enclave release  --devnet DIR --log-url URL --out release.json
                             [--answer-day 2 --min-people 2 --min-nodes 1]
    anagram enclave line     --devnet DIR --log-url URL --release FILE --witness URL --witness URL
    anagram enclave failover --devnet DIR --log-url URL --release FILE --witness URL --witness URL
                             --writer INSTANCE_ID
    anagram enclave serve --profile simulated --devnet DIR --release FILE --state DIR
                          --snapshots DIR (shared by the instances of the line)
                          --log-url URL --roster-url URL [--first-line | --standby-of URL]
                          [--feed-rewrite PREFIX=URL ...] [--host H --port P]
    anagram log serve     --devnet DIR --state DIR --witness URL (3 times, witness 1 to 3)
    anagram witness serve --devnet DIR --number N --state DIR --log-url URL
    anagram roster serve  --devnet DIR --state DIR --log-url URL
    anagram roster admit  --devnet DIR --state DIR --log-url URL RECORD.json   (- for stdin)

Each command that uses a secret key takes `--key FILE`, the key file of its
service (`devnet init` writes DIR/keys/SERVICE/key.json); then it reads no
other key. Without `--key` it reads the key files under `--devnet`/keys.

Each `serve` writes JSON log lines to stderr (no pack text, no key, no
subject), answers `GET /healthz`, stops on SIGTERM, and keeps its state in
`--state`. The `--witness` options of `line` and `failover` are the two
independent witnesses (2 and 3). See docs/enclave.md.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

from anagram.core.errors import ClientError

TIMEOUT = 30.0


def _devnet(args):
    from anagram.network.api import DevNet

    key = getattr(args, "key", None)
    net = DevNet(Path(args.devnet), key_file=Path(key) if key else None)
    if not net.pins_path.exists():
        raise ClientError(f"no development network in {net.dir}; run `anagram enclave devnet init`")
    return net


def _client(url: str):
    import httpx

    return httpx.Client(base_url=url, timeout=TIMEOUT)


def _log(net, url: str):
    from anagram.network.api import HttpLog

    pins = net.pins()
    return HttpLog(pins.origin, pins.roots, _client(url))


def _operator(args):
    from anagram.core.devclock import clock_from_env
    from anagram.network.api import Operator

    net = _devnet(args)
    witnesses = [_client(u) for u in args.witness or []]
    return Operator(net, _log(net, args.log_url), witnesses, clock_from_env())


def cmd_devnet_init(args) -> int:
    from anagram.network.api import init_devnet

    net = init_devnet(args.dir, args.network, args.origin, args.keys)
    print(f"Development network {args.network} in {net.dir}")
    print(f"Pins (for nodes and apps): {net.pins_path}")
    print(f"Key files (one for each service): {net.keys_dir}")
    print("SIMULATED PROFILE: development only; it protects nothing.")
    return 0


def cmd_release(args) -> int:
    rel = _operator(args).release(args.answer_day, args.min_people, args.min_nodes)
    rel.write(args.out)
    print(f"Release logged; not before {rel.release['not_before']}. Line ID: {rel.line_id}")
    print(f"Release file: {args.out}")
    return 0


def cmd_line(args) -> int:
    from anagram.network.api import ReleaseFile

    if len(args.witness or []) != 2:
        raise ClientError("give the two independent witnesses (--witness URL twice)")
    rel = ReleaseFile.read(args.release)
    _operator(args).authorise_line(rel)
    print(f"Line {rel.line_id} authorised and cosigned by both independent witnesses.")
    return 0


def cmd_failover(args) -> int:
    from anagram.network.api import ReleaseFile

    if len(args.witness or []) != 2:
        raise ClientError("give the two independent witnesses (--witness URL twice)")
    rel = ReleaseFile.read(args.release)
    _operator(args).fail_over(rel.line_id, args.writer)
    print(f"Failover logged: {args.writer} writes line {rel.line_id}.")
    return 0


def _rewrites(values: list[str] | None) -> dict[str, str]:
    out = {}
    for v in values or []:
        prefix, sep, url = v.partition("=")
        if not sep or not url:
            raise ClientError(f"--feed-rewrite needs PREFIX=URL, not {v!r}")
        out[prefix] = url
    return out


def cmd_enclave_serve(args) -> int:  # pragma: no cover - runs a server
    from anagram.core.devclock import clock_from_env
    from anagram.network.api import (
        EnclaveHost,
        HttpFeed,
        ReleaseFile,
        enclave_app,
        serve_service,
        setup_service_logging,
    )

    if args.profile != "simulated":
        raise ClientError("this build runs only the simulated profile")
    if args.first_line and args.standby_of:
        raise ClientError("an instance starts the line or is a standby, not both")
    setup_service_logging("enclave")
    net = _devnet(args)
    clock = clock_from_env()
    feed = HttpFeed(_client(args.roster_url), _rewrites(args.feed_rewrite))
    host = EnclaveHost.open(
        Path(args.state),
        ReleaseFile.read(args.release),
        net.pins().roots,
        _log(net, args.log_url),
        feed,
        clock,
        net.key("dev-root"),
        Path(args.snapshots),
    )
    if args.standby_of:
        host.standby_of = _client(args.standby_of)
    serve_service(enclave_app(host, first_line=args.first_line), args.host, args.port)
    return 0


def cmd_log_serve(args) -> int:  # pragma: no cover - runs a server
    from anagram.core.devclock import clock_from_env
    from anagram.network.api import (
        HttpCosigner,
        LogService,
        LogStore,
        TransparencyLog,
        log_app,
        serve_service,
        setup_service_logging,
        witness_name,
    )

    if len(args.witness or []) != 3:
        raise ClientError("give the three witnesses in order (--witness URL three times)")
    setup_service_logging("log")
    net = _devnet(args)
    pins = net.pins()
    state = Path(args.state)
    state.mkdir(parents=True, exist_ok=True)
    clock = clock_from_env()
    cosigners = [
        HttpCosigner(witness_name(pins.network, n), _client(url))
        for n, url in enumerate(args.witness, start=1)
    ]
    log = TransparencyLog(
        pins.origin, net.key("log"), pins.roots, clock, cosigners, LogStore(state / "log.sqlite")
    )
    serve_service(log_app(LogService(log, clock)), args.host, args.port)
    return 0


def cmd_witness_serve(args) -> int:  # pragma: no cover - runs a server
    from anagram.core.devclock import clock_from_env
    from anagram.network.api import (
        EntryWitness,
        LogStore,
        serve_service,
        setup_service_logging,
        witness_app,
    )

    setup_service_logging(f"witness-{args.number}")
    net = _devnet(args)
    pins = net.pins()
    pin = next((w for w in pins.witnesses if w.name.startswith(f"witness-{args.number}.")), None)
    if pin is None:
        raise ClientError(f"no witness {args.number} in the development network")
    state = Path(args.state)
    state.mkdir(parents=True, exist_ok=True)
    cosign, entry = net.witness_keys(args.number)
    witness = EntryWitness(
        pin.name,
        cosign,
        entry,
        pin.reads_entries,
        pins.roots.log_key,
        pins.roots,
        clock_from_env(),
        state=state / "witness.sqlite",
        store=LogStore(state / "entries.sqlite") if pin.reads_entries else None,
    )
    serve_service(witness_app(witness, _log(net, args.log_url)), args.host, args.port)
    return 0


def _roster(args):
    from anagram.core.devclock import clock_from_env
    from anagram.network.api import RosterService, RosterStore

    net = _devnet(args)
    state = Path(args.state)
    state.mkdir(parents=True, exist_ok=True)
    return RosterService(
        net.pins().network,
        net.key("roster"),
        RosterStore(state / "roster.sqlite"),
        _log(net, args.log_url),
        clock_from_env(),
    )


def cmd_roster_serve(args) -> int:  # pragma: no cover - runs a server
    from anagram.network.api import roster_app, serve_service, setup_service_logging

    setup_service_logging("roster")
    service = _roster(args)
    serve_service(roster_app(service), args.host, args.port)
    return 0


def cmd_roster_admit(args) -> int:
    text = sys.stdin.read() if args.record == "-" else Path(args.record).read_text()
    service = _roster(args)
    service.start()
    try:
        ev = service.admit(json.loads(text))
    except ValueError as exc:
        raise ClientError(str(exc)) from exc
    print(f"Admitted {ev['body']['node']['id']} at roster seq {ev['seq']}.")
    return 0


def cmd_roster_remove(args) -> int:
    service = _roster(args)
    service.start()
    try:
        ev = service.remove(args.node, args.reason)
    except ValueError as exc:
        raise ClientError(str(exc)) from exc
    print(f"Removed {args.node} ({args.reason}) at roster seq {ev['seq']}.")
    return 0


def _key_arg(p) -> None:
    p.add_argument("--key", help="the key file of this service (read no other key)")


def _serve_args(p, port: int) -> None:
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=port)


def register(sub) -> None:
    """Add `anagram enclave`, `anagram log`, `anagram witness` and `anagram roster`."""
    _register_enclave(sub)
    _register_services(sub)


def _register_enclave(sub) -> None:
    p = sub.add_parser("enclave", help="matching enclave processes (simulated profile)")
    esub = p.add_subparsers(dest="enclave_command", required=True)
    s = esub.add_parser("devnet", help="the keys of a development network")
    dsub = s.add_subparsers(dest="devnet_command", required=True)
    d = dsub.add_parser("init", help="make the keys and devnet.json")
    d.add_argument("--dir", required=True)
    d.add_argument("--network", required=True, help="network ID, e.g. net.anagram.localhost")
    d.add_argument("--origin", required=True, help="log origin, e.g. log.anagram.localhost/enclave")
    d.add_argument("--keys", help="directory of the key files (default: DIR/keys)")
    d.set_defaults(func=cmd_devnet_init)
    for name, func, text in (
        ("release", cmd_release, "log a release (release key)"),
        ("line", cmd_line, "authorise the first line of the release"),
        ("failover", cmd_failover, "name a standby the writer of the line"),
    ):
        s = esub.add_parser(name, help=text)
        s.add_argument("--devnet", required=True)
        _key_arg(s)
        s.add_argument("--log-url", required=True)
        s.add_argument("--witness", action="append", help="URL of an independent witness")
        s.set_defaults(func=func)
        if name == "release":
            s.add_argument("--out", required=True)
            s.add_argument("--answer-day", type=int, default=2)
            s.add_argument("--min-people", type=int, default=2)
            s.add_argument("--min-nodes", type=int, default=1)
        else:
            s.add_argument("--release", required=True)
        if name == "failover":
            s.add_argument("--writer", required=True, help="instance ID of the standby")
    s = esub.add_parser("serve", help="run one enclave instance")
    s.add_argument("--profile", required=True, choices=["simulated"])
    s.add_argument("--devnet", required=True)
    _key_arg(s)
    s.add_argument("--release", required=True)
    s.add_argument("--state", required=True)
    s.add_argument("--snapshots", required=True, help="sealed snapshots, shared by the line")
    s.add_argument("--log-url", required=True)
    s.add_argument("--roster-url", required=True)
    s.add_argument("--first-line", action="store_true", help="the first instance of the line")
    s.add_argument("--standby-of", help="URL of the writer: become a standby")
    s.add_argument("--feed-rewrite", action="append", help="PREFIX=URL: read node chains here")
    _serve_args(s, 8790)
    s.set_defaults(func=cmd_enclave_serve)


def _register_services(sub) -> None:
    p = sub.add_parser("log", help="the enclave transparency log (simulated profile)")
    lsub = p.add_subparsers(dest="log_command", required=True)
    s = lsub.add_parser("serve")
    s.add_argument("--devnet", required=True)
    _key_arg(s)
    s.add_argument("--state", required=True)
    s.add_argument("--witness", action="append", help="witness URL, in order 1 to 3")
    _serve_args(s, 8780)
    s.set_defaults(func=cmd_log_serve)

    p = sub.add_parser("witness", help="one witness of the enclave log (simulated profile)")
    wsub = p.add_subparsers(dest="witness_command", required=True)
    s = wsub.add_parser("serve")
    s.add_argument("--devnet", required=True)
    _key_arg(s)
    s.add_argument("--number", type=int, required=True, choices=[1, 2, 3])
    s.add_argument("--state", required=True)
    s.add_argument("--log-url", required=True)
    _serve_args(s, 8781)
    s.set_defaults(func=cmd_witness_serve)

    p = sub.add_parser("roster", help="the network roster (simulated profile)")
    rsub = p.add_subparsers(dest="roster_command", required=True)
    for name in ("serve", "admit", "remove"):
        s = rsub.add_parser(name)
        s.add_argument("--devnet", required=True)
        _key_arg(s)
        s.add_argument("--state", required=True)
        s.add_argument("--log-url", required=True)
        if name == "serve":
            _serve_args(s, 8782)
            s.set_defaults(func=cmd_roster_serve)
        elif name == "admit":
            s.add_argument("record", help="node record JSON file, or - for stdin")
            s.set_defaults(func=cmd_roster_admit)
        else:
            s.add_argument("node", help="the node ID")
            s.add_argument("--reason", default="abuse", help="abuse, compromised, left or other")
            s.set_defaults(func=cmd_roster_remove)
