"""First start of a deployed node from environment variables (`anagram node start`).

The container runs `anagram node start`. If the node directory has no
node.json, it makes the node from the environment and prints the first
organizer invite. Then (and at each later start) it serves the node.

Environment (see docs/deploy.md):

    ANAGRAM_DOMAIN                 required, for example anagram.example.org
    ANAGRAM_PUBLIC_URL             default https://<domain> (set it if a port is used)
    ANAGRAM_COMMUNITY              community name
    ANAGRAM_ORCID_CLIENT_ID        ORCID client (required unless dev mode)
    ANAGRAM_ORCID_CLIENT_SECRET
    ANAGRAM_ORCID_SANDBOX=1        use sandbox.orcid.org
    ANAGRAM_DEV_FAKE_ORCID=1       LOCAL TESTS ONLY: fake ORCID and fake anchor.
                                   Refused unless the domain is localhost or *.localhost
    ANAGRAM_ORGANIZER_ORCIDS       optional comma list; they become organizers when they join
    ANAGRAM_TSA_URLS               comma list (default: FreeTSA and DigiCert)
    ANAGRAM_OTS=off                no OpenTimestamps (default on)
    ANAGRAM_OTS_CALENDARS          comma list of calendar URLs (default: public calendars)
    ANAGRAM_ANCHORS                full anchor list (overrides the three above)
    ANAGRAM_ANCHOR_BATCH_SECONDS   default 600
    ANAGRAM_SMTP_HOST, _PORT, _FROM, _USER, _PASSWORD   email sign-in (read at each start)
    ANAGRAM_LAB_QUOTA_MB           ciphertext quota of each lab (default 2048; read at each start)
    ANAGRAM_LAB_CREATE             organizer_invite (default: an organizer, or a member who came
                                   in with a node invite) or member (each node member); read at
                                   each start

Matching runs only in the matching enclave of the network; the node relays
sealed messages to it (simulated profile; development only; read at each
start; matching is off when ANAGRAM_ENCLAVE_URLS is not set):

    ANAGRAM_ENCLAVE_URLS           comma list of the enclave instance URLs (writer, standby)
    ANAGRAM_ENCLAVE_LOG_URL        URL of the enclave log
    ANAGRAM_ENCLAVE_PINS           path of the network pins (devnet.json)
    ANAGRAM_ENCLAVE_AFFILIATION    affiliation of the node record
    ANAGRAM_ENCLAVE_ADMIN          contact address of the node admin
    ANAGRAM_ENCLAVE_ROR            optional ROR ID; ANAGRAM_ENCLAVE_KIND lab (default),
                                   university or individual
    ANAGRAM_ENCLAVE_TICK_SECONDS   the relay timer (default 60)

The other values are read once, at the first start, and written to node.json. To
change them later, edit node.json (see docs/deploy.md). ORCID client ID and
secret and the public URL can also change through the environment at each start.
"""

from __future__ import annotations

import json
import sys
import urllib.parse
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from pathlib import Path

from anagram.proofs.anchors.defaults import DEFAULT_TSAS
from anagram.shell.node.home import NodeHome, check_anchor_policy

TRUE = ("1", "true", "yes", "on")
DEV_BANNER = """
#####################################################################
#  DEV MODE: FAKE ORCID AND FAKE ANCHORS. LOCAL TESTS ONLY.          #
#  Anyone can sign in as any ORCID iD. Proofs have NO independent    #
#  time. Never use this mode for a real community.                   #
#####################################################################
"""


class SetupError(ValueError):
    pass


def is_local_host(host: str | None) -> bool:
    """localhost, *.localhost, or a loopback address."""
    if not host:
        return False
    host = host.lower().rstrip(".")
    return host == "localhost" or host.endswith(".localhost") or host in ("127.0.0.1", "::1")


def check_dev_guard(public_url: str, dev: bool) -> None:
    """Dev mode (fake ORCID) is allowed only on a local host name."""
    host = urllib.parse.urlsplit(public_url).hostname
    if dev and not is_local_host(host):
        raise SetupError(
            f"dev mode (fake ORCID) is refused for {host!r}: use it only with localhost "
            "or a *.localhost name"
        )


@dataclass
class DeploySettings:
    domain: str
    public_url: str
    community: str
    dev: bool
    orcid_mode: str
    orcid_client_id: str
    orcid_client_secret: str = field(repr=False)
    anchors: list[str]
    anchor_batch_seconds: int
    organizers: list[str]

    @property
    def origin(self) -> str:
        from anagram.shell.node.home import LOG_ORIGIN_PATH

        return self.domain.split(":")[0] + "/" + LOG_ORIGIN_PATH


def _list(value: str | None) -> list[str]:
    return [v.strip() for v in (value or "").split(",") if v.strip()]


def _int(env: Mapping[str, str], name: str, default: int, low: int = 0) -> int:
    raw = env.get(name)
    if raw is None or raw == "":
        return default
    try:
        value = int(raw)
    except ValueError as exc:
        raise SetupError(f"{name} must be a whole number") from exc
    if value < low:
        raise SetupError(f"{name} must be {low} or more")
    return value


def _anchors_from_env(env: Mapping[str, str], mode: str, dev: bool) -> list[str]:
    """The anchor specs: ANAGRAM_ANCHORS, else the fake anchor for a dev node,
    else the TSA URLs and OpenTimestamps. Check them against the policy."""
    if env.get("ANAGRAM_ANCHORS"):
        anchors = _list(env["ANAGRAM_ANCHORS"])
    elif dev:
        anchors = ["fake"]
    else:
        anchors = [f"rfc3161:{u}" for u in _list(env.get("ANAGRAM_TSA_URLS")) or DEFAULT_TSAS]
        if (env.get("ANAGRAM_OTS") or "on").lower() not in ("0", "off", "false", "no"):
            calendars = _list(env.get("ANAGRAM_OTS_CALENDARS"))
            anchors.append(
                "opentimestamps:" + ",".join(calendars) if calendars else "opentimestamps"
            )
    try:
        check_anchor_policy(mode, anchors)
    except ValueError as exc:
        raise SetupError(str(exc)) from exc
    for spec in anchors:
        if spec.startswith("rfc3161:") and not spec.startswith(
            ("rfc3161:https://", "rfc3161:http://")
        ):
            raise SetupError(f"bad TSA URL in {spec!r}")
    return anchors


def settings_from_env(env: Mapping[str, str]) -> DeploySettings:
    domain = (env.get("ANAGRAM_DOMAIN") or "").strip().lower()
    if not domain or "/" in domain:
        raise SetupError("set ANAGRAM_DOMAIN to the host name of this node (no https://)")
    public_url = (env.get("ANAGRAM_PUBLIC_URL") or f"https://{domain}").rstrip("/")
    if urllib.parse.urlsplit(public_url).hostname != domain.split(":")[0]:
        raise SetupError("ANAGRAM_PUBLIC_URL must use the host of ANAGRAM_DOMAIN")
    dev = (env.get("ANAGRAM_DEV_FAKE_ORCID") or "").lower() in TRUE
    check_dev_guard(public_url, dev)
    if not dev and not public_url.startswith("https://"):
        raise SetupError("a real node needs an https:// public URL")

    client_id = env.get("ANAGRAM_ORCID_CLIENT_ID", "")
    secret = env.get("ANAGRAM_ORCID_CLIENT_SECRET", "")
    if dev:
        mode = "fake"
    else:
        mode = (
            "sandbox" if (env.get("ANAGRAM_ORCID_SANDBOX") or "").lower() in TRUE else "production"
        )
        if not client_id or not secret:
            raise SetupError(
                "set ANAGRAM_ORCID_CLIENT_ID and ANAGRAM_ORCID_CLIENT_SECRET "
                f"(redirect URI to register: {public_url}/auth/orcid/callback)"
            )

    anchors = _anchors_from_env(env, mode, dev)
    try:  # a bad lab setting stops the first start, not the first lab
        from anagram.network.api import lab_policy_from_env

        lab_policy_from_env(env)
    except ValueError as exc:
        raise SetupError(str(exc)) from exc
    return DeploySettings(
        domain=domain,
        public_url=public_url,
        community=(env.get("ANAGRAM_COMMUNITY") or "Anagram community").strip(),
        dev=dev,
        orcid_mode=mode,
        orcid_client_id=client_id,
        orcid_client_secret=secret,
        anchors=anchors,
        anchor_batch_seconds=_int(env, "ANAGRAM_ANCHOR_BATCH_SECONDS", 600, low=1),
        organizers=_list(env.get("ANAGRAM_ORGANIZER_ORCIDS")),
    )


def create_from_settings(nh: NodeHome, s: DeploySettings) -> None:
    nh.create(
        origin=s.origin,
        anchors=s.anchors,
        community=s.community,
        public_url=s.public_url,
        orcid_mode=s.orcid_mode,
        orcid_client_id=s.orcid_client_id,
        orcid_client_secret=s.orcid_client_secret,
        organizers=s.organizers,
        anchor_mode="background",
        anchor_batch_seconds=s.anchor_batch_seconds,
    )


def check_existing(nh: NodeHome) -> None:
    """Checks at each start of an existing node."""
    cfg = nh.config()
    check_dev_guard(cfg["public_url"], cfg["orcid"]["mode"] == "fake")
    check_anchor_policy(cfg["orcid"]["mode"], cfg["anchors"])


def enclave_from_env(env: Mapping[str, str]) -> dict | None:
    """node.json "enclave" from ANAGRAM_ENCLAVE_*, or None when it is not set."""
    urls = _list(env.get("ANAGRAM_ENCLAVE_URLS"))
    if not urls:
        return None
    pins_path = (env.get("ANAGRAM_ENCLAVE_PINS") or "").strip()
    try:
        pins = json.loads(Path(pins_path).read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise SetupError(f"ANAGRAM_ENCLAVE_PINS: cannot read the pins ({exc})") from None
    return {
        "enabled": True,
        "log_url": (env.get("ANAGRAM_ENCLAVE_LOG_URL") or "").strip(),
        "pins": pins,
        "profile": "simulated",
        "record": {
            "admin": (env.get("ANAGRAM_ENCLAVE_ADMIN") or "").strip(),
            "affiliation": (env.get("ANAGRAM_ENCLAVE_AFFILIATION") or "").strip(),
            "kind": (env.get("ANAGRAM_ENCLAVE_KIND") or "lab").strip(),
            "ror": (env.get("ANAGRAM_ENCLAVE_ROR") or "").strip() or None,
        },
        "urls": urls,
        **(
            {"tick_seconds": float(tick)}
            if (tick := env.get("ANAGRAM_ENCLAVE_TICK_SECONDS"))
            else {}
        ),
    }


def enclave_line(nh: NodeHome) -> str:
    cfg = nh.enclave_config()
    if not cfg["enabled"]:
        return "Matching enclave: off."
    return (
        f"Matching enclave: on ({cfg['profile']} profile: DEVELOPMENT ONLY, no privacy);"
        f" node ID {nh.node_record()['id']}"
    )


def prepare(
    nh: NodeHome,
    env: Mapping[str, str],
    out: Callable[[str], None] = print,
) -> str | None:
    """Make the node on the first start (and return the first organizer invite
    link), or check an existing node (and return None)."""
    created = None
    if not nh.exists():
        s = settings_from_env(env)
        create_from_settings(nh, s)
        created = nh.admission(nh.identity(nh.service())).create_invite(None, 30, organizer=True)
    check_existing(nh)
    enclave = enclave_from_env(env)
    if enclave is not None:
        nh.set_enclave(enclave)
    cfg = nh.config()
    if cfg["orcid"]["mode"] == "fake":
        out(DEV_BANNER)
    out(f"Community: {cfg['community']}")
    out(f"Public URL: {cfg['public_url']}")
    out(f"ORCID: {cfg['orcid']['mode']}; redirect URI: {cfg['public_url']}/auth/orcid/callback")
    out(f"Anchors: {', '.join(cfg['anchors']) or 'none'} ({cfg['anchor_mode']})")
    out(enclave_line(nh))
    out(f"Node key fingerprint: {nh.fingerprint()}")
    if created is None:
        return None
    link = created["invite_url"]
    out("")
    out("FIRST ORGANIZER INVITE (single use, 30 days). Open it with Anagram:")
    out(f"  {link}")
    out("More invites: `anagram node invite` (add --organizer for an organizer),")
    out(f"or the organizer page: {cfg['public_url']}/admin")
    out("")
    return link


def serve_node(
    nh: NodeHome, host: str, port: int, *, proxy: bool = False
) -> int:  # pragma: no cover - server
    """Serve the node with its timers: background anchors, and the enclave
    relay (node.json "enclave" on). The timers stop
    when the server stops (SIGTERM or SIGINT)."""
    import uvicorn

    from anagram.identity.api import mailer_from_env
    from anagram.network.api import Ticker

    app, _ = nh.app_parts(mailer=mailer_from_env())
    enclave = app.state.enclave
    tickers = []
    if enclave is not None:
        tickers.append(Ticker("enclave-relay", enclave.relay.tick, enclave.tick_seconds).start())
    stops = []
    if app.state.anchoring is not None:
        stops.append(app.state.anchoring.start())
    extra = {"proxy_headers": True, "forwarded_allow_ips": "*"} if proxy else {}
    try:
        uvicorn.run(app, host=host, port=port, **extra)
    finally:
        for stop in stops:
            stop.set()
        for ticker in tickers:
            ticker.stop()
        if enclave is not None:
            enclave.close()
    return 0


def main_start(nh: NodeHome, host: str, port: int) -> int:  # pragma: no cover - server
    import logging
    import os

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(levelname)s %(message)s")
    try:
        prepare(nh, os.environ, out=lambda line: print(line, flush=True))
    except (SetupError, ValueError) as exc:
        print(f"anagram: cannot start: {exc}", file=sys.stderr, flush=True)
        return 2
    return serve_node(nh, host, port, proxy=True)
