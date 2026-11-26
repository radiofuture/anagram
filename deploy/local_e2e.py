"""Local end-to-end test of a real deployment (Docker Compose, Caddy HTTPS).

Run it through `deploy/local-e2e.sh` (from the repository root):

1. Build the node image and start Compose in local dev mode
   (https://anagram.localhost:8443, Caddy's own CA, fake ORCID).
2. Read the first organizer invite from the node log; make more invites with
   `docker compose exec node anagram node invite`.
3. Copy Caddy's root certificate out and trust it in the client processes only
   (SSL_CERT_FILE = system roots + Caddy root).
4. Three people in two labs (`lab_scenario`). Each joins
   with the real `anagram join` CLI in a separate client home: Chen and
   Okafor with node invites, Ruiz with a lab invite link of the Chen Lab. Then,
   through the client API: lab space (Ruiz writes, Chen reads, Okafor cannot),
   and a finding that Chen shares with Okafor and the read receipt.
5. Chen commits one finding with the CLI and verifies its file proof.
6. Matching, only through the enclave, simulated profile (deploy/enclave_e2e.py):
   log, 3 witnesses, roster, enclave writer and standby, 2 nodes, 4 people;
   a both-or-neither reveal, a withdrawal, a restart from sealed state, a
   writer failover, and a scan of the logs.
7. Tear down (unless --keep).

The script touches only the Compose project "anagram-e2e". The in-process
test `tests/test_local_e2e_scenario.py` runs `lab_scenario` offline.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import ssl
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
WORK = HERE / ".e2e"
PROJECT = "anagram-e2e"
PORT = int(os.environ.get("ANAGRAM_LOCAL_PORT", "8443"))
NODE = f"https://anagram.localhost:{PORT}"
COMPOSE = [
    "docker",
    "compose",
    "-p",
    PROJECT,
    "-f",
    str(HERE / "compose.yaml"),
    "-f",
    str(HERE / "compose.local.yaml"),
    "-f",
    str(HERE / "compose.enclave.yaml"),
]
# The enclave instances start later (deploy/enclave_e2e.py), after the release.
BASE_SERVICES = ["node", "node-b", "caddy", "log", "witness-1", "witness-2", "witness-3", "roster"]
CLOCK = WORK / "clock" / "offset"
CA_PATH = "/data/caddy/pki/authorities/local/root.crt"


def say(text: str) -> None:
    print(f"[e2e] {text}", flush=True)


def check(ok: bool, detail: object) -> None:
    if not ok:
        raise SystemExit(f"[e2e] FAIL: {detail}")


def run(cmd: list[str], *, env=None, check=True, capture=True, input=None) -> str:  # noqa: A002
    r = subprocess.run(  # noqa: S603
        cmd, env=env, text=True, capture_output=capture, check=False, input=input
    )
    if check and r.returncode != 0:
        raise SystemExit(
            f"command failed ({r.returncode}): {' '.join(cmd)}\n{r.stdout or ''}{r.stderr or ''}"
        )
    return (r.stdout or "") + (r.stderr or "")


def compose(*args: str, check=True, capture=True, input=None) -> str:  # noqa: A002
    return run([*COMPOSE, *args], check=check, capture=capture, input=input)


def wait_for(what: str, fn, timeout: float, every: float = 2.0):
    end = time.time() + timeout
    while True:
        value = fn()
        if value:
            return value
        if time.time() > end:
            raise SystemExit(f"timeout: {what}")
        time.sleep(every)


def ca_bundle() -> Path:
    WORK.mkdir(parents=True, exist_ok=True)
    local = HERE / "local-ca.crt"

    def copy() -> bool:
        out = subprocess.run(  # noqa: S603
            [*COMPOSE, "cp", f"caddy:{CA_PATH}", str(local)], capture_output=True, check=False
        )
        return out.returncode == 0 and local.exists()

    wait_for("Caddy local CA root", copy, 60)
    system = Path(ssl.get_default_verify_paths().cafile or "/etc/ssl/cert.pem")
    if not system.exists():
        system = Path("/etc/ssl/cert.pem")
    bundle = WORK / "ca-bundle.pem"
    bundle.write_text((system.read_text() if system.exists() else "") + "\n" + local.read_text())
    return bundle


def https_get(path: str, bundle: Path) -> tuple[int, str]:
    ctx = ssl.create_default_context(cafile=str(bundle))
    try:
        with urllib.request.urlopen(NODE + path, context=ctx, timeout=10) as r:  # noqa: S310
            return r.status, r.read().decode()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode()


def first_invite(service: str = "node") -> str:
    def find():
        m = re.search(
            r"FIRST ORGANIZER INVITE.*?\n.*?(https://\S+/join#\S+)", compose("logs", service)
        )
        return m.group(1) if m else None

    return wait_for(f"first organizer invite in the {service} log", find, 60)


def cli(home: Path, env: dict, *args: str) -> str:
    out = run(["uv", "run", "--quiet", "anagram", "--home", str(home), *args], env=env)
    return out


# ------------------------------------------------- three people in two labs
#
# The same steps run in two places: on the Docker stack
# (`main`, below) and in process in the offline suite
# (tests/test_local_e2e_scenario.py). The caller gives three functions:
#
#   node_invite() -> str                    a new node invite link
#   join(slug, link, orcid, name) -> Client a new member home, joined

SCENARIO_PEOPLE = {
    # slug: (ORCID iD, name, institution, lab slug)
    "chen": ("fake-0000-0007-1404-5686", "Mei-Lin Chen", "fake-ror-9148b7c00", "chen"),
    "ruiz": ("fake-0000-0001-9322-6174", "Ana Ruiz", "fake-ror-9148b7c00", "chen"),
    "okafor": ("fake-0000-0009-4289-3031", "Chidi Okafor", "fake-ror-9148b7c00", "okafor"),
}


def lab_scenario(node_invite, join, work: Path, log=None) -> dict:
    """Three people in two labs: lab space and a shared finding with a read
    receipt. Raise SystemExit (by `check`) at the first fault. Return a short
    summary."""
    from anagram.network.groups.app.labrecords import LabItemDraft

    log = log or say
    people: dict = {}

    def ident(slug: str, c, lab_id: str) -> None:
        _, name, ror, _ = SCENARIO_PEOPLE[slug]
        c.account.set_identity(name, institution=ror, lab_id=lab_id)

    # 1. Two lab leaders join the node and each makes a lab.
    labs = {}
    for slug, lab_name in (("chen", "Chen Lab"), ("okafor", "Okafor Lab")):
        orcid, name, _, _ = SCENARIO_PEOPLE[slug]
        c = join(slug, node_invite(), orcid, name)
        labs[slug] = c.labs.lab_create(lab_name)["lab_id"]
        ident(slug, c, labs[slug])
        people[slug] = c
    chen, okafor = people["chen"], people["okafor"]
    log("Chen and Okafor joined the node; each made a lab")

    # 2. A new person joins the node and the Chen Lab with one lab invite link.
    link = chen.admission.lab_invite(labs["chen"])["url"]
    orcid, name, _, _ = SCENARIO_PEOPLE["ruiz"]
    ruiz = join("ruiz", link, orcid, name)
    ident("ruiz", ruiz, labs["chen"])
    people["ruiz"] = ruiz
    chen.labs.lab_sync(labs["chen"])
    check(
        chen.lab_roster.lab_members(labs["chen"]) == {chen.device.subject, ruiz.device.subject},
        "Chen Lab roster",
    )
    log("Ruiz joined the node and the Chen Lab from a lab invite link")

    # 3. Lab space: Ruiz writes a note; Chen reads it; Okafor cannot.
    origin = {"media_type": "text/markdown", "name": "notes.md", "source_kind": "folder"}
    item = ruiz.lab_space.lab_publish(
        labs["chen"],
        LabItemDraft(kind="note", title="Nanodisc yield", text="Yield went up 2 times.",
                     origin=origin),
    )  # fmt: skip
    chen.labs.lab_sync(labs["chen"])
    check(
        chen.lab_space.lab_item(labs["chen"], item)["text"] == "Yield went up 2 times.", "lab item"
    )
    check(labs["chen"] not in okafor.lab_keys.readable_labs(), "Okafor must not read the Chen Lab")
    log("lab space: Ruiz published a note, Chen read it, Okafor cannot")

    # 4. Chen shares a finding with Okafor (other lab); Chen gets a read receipt.
    note = work / "chen-finding.md"
    note.write_text("# Result\nThe transporter binds the ligand in the outward-open state.\n")
    root = chen.findings.commit_finding([note], claim="Outward-open binding").subject.root.hex()
    target = chen.shares.resolve_target(okafor.device.subject)["target"]
    out = chen.shares.share(root, [target])
    check(out["shared"] == [{"people": 1, "target": okafor.device.subject}], out)
    grants = [g for g in okafor.grants.inbox() if g.get("root", root) == root]
    check(len(grants) == 1, okafor.grants.inbox())
    opened = okafor.grants.open_grant(grants[0]["grant_id"], work / "okafor-received")
    check(opened["root"] == root and opened["verified"], opened)
    reads = [r for r in chen.read_records.sync_reads() if r["kind"] == "read"]
    check(len(reads) == 1 and reads[0]["reader"] == okafor.device.subject, reads)
    check(ruiz.grants.inbox() == [], "Ruiz got no grant")
    log("sharing: Chen shared a finding with Okafor; Okafor read it; Chen has the receipt")
    return {"labs": 2, "people": 3, "reads": 1}


def enclave_part(node_invite, join) -> None:
    """Step 6: matching through the enclave (deploy/enclave_e2e.py). Alice
    and Carol join node A, Bob and Dan node B."""
    from enclave_e2e import Network, enclave_scenario

    invites_b = [first_invite("node-b")]

    def enclave_join(node: str, slug: str, name: str):
        if node == "A":
            link = node_invite()
        elif invites_b:
            link = invites_b.pop()
        else:
            out = compose("exec", "-T", "node-b", "anagram", "node", "invite")
            link = re.search(r"https://\S+/join#\S+", out).group(0)
        return join(slug, link, f"fake-e2e-{slug}", name)

    enclave_scenario(Network(compose, CLOCK, say, check), enclave_join)


def cli_finding(home: Path, env: dict) -> None:
    """The CLI path of a finding: commit, prove one file, verify with anchors."""
    note = home / "finding.txt"
    note.write_text("Chen Lab: first result for the local deployment test.\n")
    out = cli(home, env, "commit", str(note), "--claim", "Chen Lab result",
              "--out", str(home / "proof.json"))  # fmt: skip
    check("Committed finding" in out, out)
    root = re.search(r"Root: ([0-9a-f]{64})", out).group(1)
    file_proof = home / "file-proof.json"
    cli(home, env, "prove-file", root, str(note), "--out", str(file_proof))
    out = cli(home, env, "verify", str(file_proof), "--file", str(note))
    check(out.startswith("VALID") and "anchors that back this proof" in out, out)
    say("CLI: Chen timestamped one finding and verified it")


def clean_start() -> None:
    say("clean start: compose down -v (project anagram-e2e only)")
    compose("down", "-v", "--remove-orphans", check=False)
    if WORK.exists():
        shutil.rmtree(WORK)
    CLOCK.parent.mkdir(parents=True)
    CLOCK.write_text("0\n")  # the development clock of the enclave processes
    os.environ["ANAGRAM_DEV_CLOCK_FILE"] = str(CLOCK)  # the apps in this process


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--keep", action="store_true", help="leave the deployment running")
    ap.add_argument("--no-build", action="store_true")
    a = ap.parse_args()

    sys.path.insert(0, str(ROOT / "src"))
    sys.path.insert(0, str(HERE))
    from anagram.shell.client import Client

    clean_start()
    try:
        say("build and start (this can take some minutes the first time)")
        up = ["up", "-d", "--wait", "--wait-timeout", "180"]
        if not a.no_build:
            up.append("--build")
        compose(*up, *BASE_SERVICES, capture=False)
        bundle = ca_bundle()
        env = {**os.environ, "SSL_CERT_FILE": str(bundle)}
        env.pop("ANAGRAM_HOME", None)
        env.pop("ANAGRAM_NODE_HOME", None)
        os.environ["SSL_CERT_FILE"] = str(bundle)  # the clients in this process

        status, trust = wait_for(
            "node over HTTPS",
            lambda: (lambda r: r if r[0] == 200 else None)(https_get("/node/trust", bundle)),
            60,
        )
        doc = json.loads(trust)
        check(doc["node_url"] == NODE and doc["orcid_mode"] == "fake", doc)
        say(f"node is up at {NODE} (community {doc['community']!r})")
        status, page = https_get("/admin", bundle)
        check(status == 200 and "Sign in with ORCID" in page, status)
        say("organizer page answers (login form, no data)")

        invites = [first_invite()]  # the first one makes the first person an organizer

        def node_invite() -> str:
            if invites:
                return invites.pop()
            out = compose("exec", "-T", "node", "anagram", "node", "invite")
            return re.search(r"https://\S+/join#\S+", out).group(0)

        homes: dict[str, Path] = {}

        def join(slug: str, link: str, orcid: str, name: str):
            home = WORK / "homes" / slug
            env["ANAGRAM_DEV_CLOCK_FILE"] = str(CLOCK)
            homes[slug] = home
            (WORK / "kits").mkdir(parents=True, exist_ok=True)
            out = cli(home, env, "join", link, "--fake-orcid", orcid, "--name", name,
                      "--kit-file", str(WORK / "kits" / f"{slug}.md"))  # fmt: skip
            check("Signed in as" in out, out)
            return Client(home)

        lab_scenario(node_invite, join, WORK)

        cli_finding(homes["chen"], env)

        enclave_part(node_invite, join)
        say("PASS")
        return 0
    finally:
        if a.keep:
            say(f"kept running: {NODE}  (client homes in {WORK / 'homes'})")
            say(
                f"stop with: docker compose -p {PROJECT} -f deploy/compose.yaml "
                "-f deploy/compose.local.yaml -f deploy/compose.enclave.yaml down -v"
            )
        else:
            say("tear down")
            compose("down", "-v", "--remove-orphans", check=False)


if __name__ == "__main__":
    sys.exit(main())
