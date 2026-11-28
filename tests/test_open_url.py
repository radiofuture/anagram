"""The `anagram://` links (R1 plan, section 7 and 12; integration 1.5).

`anagram open-url <link>` gives an invite to the running app as a pending
invite only. The app runs in this process on a loopback port; the node is the
in-process test node. No real URL scheme handler is registered: the scheme
classes write into a temp directory and run a fake system tool.
"""

from __future__ import annotations

import subprocess

import pytest
from conftest import make_net
from fastapi.testclient import TestClient
from test_app_control import app, browser_client  # noqa: F401 - the `app` fixture
from test_autostart import FakeRun

from anagram.shell.app import launcher, urlscheme
from anagram.shell.app.urlscheme import (
    LaunchServicesScheme,
    NoScheme,
    RegistryScheme,
    XdgScheme,
    handler_command,
    scheme_for_platform,
)
from anagram.shell.cli.main import main
from anagram.shell.ui.server import create_ui_app
from anagram.shell.ui.service import UIService


def fragment(link: str) -> str:
    return link.split("#", 1)[1]


def no_start(home):
    raise AssertionError("the app runs; the launcher must not start it")


@pytest.fixture
def lab_link(tmp_path):
    """A network with a PI, a lab, and a lab invite link of that lab."""
    net = make_net(tmp_path)
    pi = net.join(tmp_path / "pi", "fake-url-pi", "Mei Chen").client
    lab_id = pi.labs.lab_create("Chen Lab")["lab_id"]
    return net, pi, lab_id, pi.admission.lab_invite(lab_id)["url"]


# ------------------------------------------------------------- link parsing


def test_invite_of_gives_the_https_link(lab_link):
    net, _, _, lab = lab_link
    node_invite = net.invite()
    assert launcher.invite_of(f"anagram://join/{fragment(node_invite)}") == node_invite
    assert launcher.invite_of(f"anagram://join/{fragment(lab)}") == lab
    for bad in (
        "anagram://open",
        "anagram://join/",
        "anagram://join/bm90LWFuLWludml0ZQ",  # base64url, not an invite
        f"anagram://join/{fragment(node_invite)}?x=1",
        f"anagram://join/{fragment(node_invite)}/../x",
        f"https://node.test/join#{fragment(node_invite)}",
    ):
        assert launcher.invite_of(bad) is None, bad


def test_open_url_rejects_options(tmp_path, monkeypatch, lab_link):
    """Only one argument that starts with `anagram://`, at most 8192
    characters. Other input opens the app with no data."""
    net, _, _, _ = lab_link
    calls = []
    monkeypatch.setattr(launcher, "open_app", lambda home, **kw: calls.append(kw) or "url")
    good = f"anagram://join/{fragment(net.invite())}"
    for argv in (
        [good, "--home", "/somewhere/else"],
        ["--home", "/somewhere/else", good],
        [good.replace("anagram://", "https://")],
        [good + "A" * (urlscheme.MAX_URL - len(good) + 1)],
        ["anagram://open"],
        [],
    ):
        calls.clear()
        launcher.open_url(tmp_path / "h", argv)
        assert calls == [{"invite": None}], argv
    launcher.open_url(tmp_path / "h", [good])
    assert calls[-1]["invite"].startswith("https://node.test/join#")
    # Case-insensitive anagram:// scheme and macOS -psn_* flag filtering.
    calls.clear()
    launcher.open_url(tmp_path / "h", ["-psn_0_12345", good.replace("anagram://", "ANAGRAM://")])
    assert calls[-1]["invite"].startswith("https://node.test/join#")


def test_open_url_command_takes_all_words_as_data(tmp_path, monkeypatch):
    seen = []
    monkeypatch.setattr(launcher, "open_app", lambda home, **kw: seen.append((home, kw)) or "u")
    home = str(tmp_path / "h")
    assert main(["--home", home, "open-url", "anagram://open", "--home", "/evil"]) == 0
    assert seen == [(home, {"invite": None})]  # the second --home is data, not an option
    assert main(["--home", home, "open-url", "anagram://open"]) == 0
    assert seen[-1] == (home, {"invite": None})


# ---------------------------------------------------- the app and the invite


def test_open_url_join_is_pending_only(tmp_path, app):  # noqa: F811
    net = make_net(tmp_path)
    home = tmp_path / "new"
    rt = app(home, service=UIService(home, transport=net.transport, clock=net.clock))
    invite = net.invite()
    opened = []
    url = launcher.open_url(
        home, [f"anagram://join/{fragment(invite)}"], start=no_start, browser=opened.append
    )
    assert opened == [url]
    c = browser_client(rt)
    assert c.get(url, follow_redirects=False).headers["location"] == "/#/welcome"
    assert rt.service.state.get("pending_invite") == {"kind": "node", "url": invite}
    assert not rt.service.joined() and rt.service.join.task is None  # no sign-in started
    info = c.get("/api/join").json()
    assert info["invite"] == invite
    assert info["community"] == "Test community" and info["host"] == "node.test"
    assert "lab" not in info


def test_open_url_ignored_when_joined(tmp_path, app):  # noqa: F811
    net = make_net(tmp_path)
    home = tmp_path / "me"
    net.join(home, "fake-url-me", "Url Person").client.vault.close()
    rt = app(home, service=UIService(home, transport=net.transport, clock=net.clock))
    before = rt.service.state.load()
    url = launcher.open_url(
        home, [f"anagram://join/{fragment(net.invite())}"], start=no_start, browser=lambda u: None
    )
    assert browser_client(rt).get(url, follow_redirects=False).headers["location"] == "/"
    assert rt.service.state.load() == before


def test_lab_invite_stays_pending_for_a_joined_home(tmp_path, app, lab_link):  # noqa: F811
    net, _, _, lab = lab_link
    home = tmp_path / "member"
    net.join(home, "fake-url-member", "Lab Member").client.vault.close()
    rt = app(home, service=UIService(home, transport=net.transport, clock=net.clock))
    url = launcher.open_url(
        home, [f"anagram://join/{fragment(lab)}"], start=no_start, browser=lambda u: None
    )
    assert browser_client(rt).get(url, follow_redirects=False).headers["location"] == "/#/lab/join"
    assert rt.service.state.get("pending_invite") == {"kind": "lab", "url": lab}
    assert rt.service.state.get("invite") != lab  # the welcome invite does not change


def test_lab_invite_for_a_new_person_shows_the_lab(tmp_path, app, lab_link):  # noqa: F811
    net, _, _, lab = lab_link
    home = tmp_path / "new"
    rt = app(home, service=UIService(home, transport=net.transport, clock=net.clock))
    url = launcher.open_url(
        home, [f"anagram://join/{fragment(lab)}"], start=no_start, browser=lambda u: None
    )
    c = browser_client(rt)
    assert c.get(url, follow_redirects=False).headers["location"] == "/#/welcome"
    assert rt.service.state.get("pending_invite") == {"kind": "lab", "url": lab}
    info = c.get("/api/join").json()
    assert info["invite"] == lab and info["lab"] == "Chen Lab"
    assert info["community"] == "Test community" and info["host"] == "node.test"


def test_join_with_the_pending_lab_invite_and_no_paste(tmp_path, lab_link):
    """A new person: one POST /api/join with no body joins the node and the
    lab (client.identity.join: `202 bind_device`, bind, send again). The
    pending invite is then used."""
    net, pi, lab_id, lab = lab_link
    port, token = 41998, "launch-token-for-tests"  # a test value
    base = f"http://127.0.0.1:{port}"
    home = tmp_path / "new"
    svc = UIService(
        home, transport=net.transport, clock=net.clock, return_to=f"{base}/auth/callback"
    )
    from anagram.shell.app.control import accept_invite

    assert accept_invite(svc, lab) == "join"
    svc.state.update(display_name="New Member")
    tc = TestClient(create_ui_app(svc, port=port, token=token), base_url=base)
    assert tc.get(f"/open/{token}", follow_redirects=False).status_code == 303
    tc.post("/api/join", json={}, headers={"Origin": base})
    svc.join.task.thread.join(30)
    assert tc.get("/api/join").json()["status"]["state"] == "joined"
    assert svc.state.get("pending_invite") is None
    with svc.session() as c:
        me = c.device.subject
    assert pi.lab_roster.lab_state(lab_id).members[me] == "member"


# ------------------------------------------------------------ scheme classes


def test_xdg_scheme_writes_a_desktop_file(tmp_path):
    run = FakeRun()
    s = XdgScheme(root=tmp_path, run=run)
    assert s.command() is None
    cmd = ["/opt/My Apps/Anagram", "--home", "/home/mei/.anagram", "open-url"]
    s.register(cmd)
    text = s.path.read_text()
    assert s.path == tmp_path / ".local/share/applications/anagram.desktop"
    assert "MimeType=x-scheme-handler/anagram;" in text and text.count("%u") == 1
    assert s.command() == cmd
    assert ["xdg-mime", "default", "anagram.desktop", "x-scheme-handler/anagram"] in run.calls
    s.unregister()
    assert not s.path.exists() and s.command() is None


def test_registry_scheme_commands(tmp_path):
    exe = r"C:\Users\Mei Chen\AppData\Local\Anagram\Anagram.exe"
    run = FakeRun()
    s = RegistryScheme(root=tmp_path, run=run)
    s.register([exe, "open-url"])
    value = run.calls[-1][run.calls[-1].index("/d") + 1]
    assert value == f'"{exe}" open-url "%1"'
    assert run.calls[0][:3] == ["reg", "add", r"HKCU\Software\Classes\anagram"]
    assert ["reg", "add", urlscheme.WIN_KEY, "/v", "URL Protocol", "/d", "", "/f"] in run.calls
    out = f"\n{urlscheme.WIN_KEY}\\shell\\open\\command\n    (Default)    REG_SZ    {value}\n"
    s = RegistryScheme(root=tmp_path, run=FakeRun(outputs={"reg query": out}))
    assert s.command() == [exe, "open-url"]
    s.unregister()
    assert s.run.calls[-1] == ["reg", "delete", urlscheme.WIN_KEY, "/f"]


def test_launch_services_scheme_needs_the_bundle(tmp_path):
    from anagram.shell.app.autostart import AutostartError

    s = LaunchServicesScheme(root=tmp_path, run=FakeRun(), bundle=None)
    with pytest.raises(AutostartError):
        s.register(["x"])
    assert s.command() is None
    bundle = tmp_path / "Anagram.app"
    assert urlscheme.bundle_of(bundle / "Contents/MacOS/Anagram") == bundle
    assert urlscheme.bundle_of(tmp_path / "bin/python3") is None
    run = FakeRun()
    s = LaunchServicesScheme(root=tmp_path, run=run, bundle=bundle)
    s.register(["x"])
    assert run.calls == [[urlscheme.LSREGISTER, "-f", str(bundle)]]
    assert s.command() == [str(bundle / "Contents/MacOS/Anagram"), "open-url"]


def test_scheme_for_platform_and_handler_command(tmp_path):
    run = FakeRun()
    assert isinstance(scheme_for_platform(root=tmp_path, run=run, platform="linux"), XdgScheme)
    assert isinstance(scheme_for_platform(root=tmp_path, run=run, platform="win32"), RegistryScheme)
    mac = scheme_for_platform(root=tmp_path, run=run, platform="darwin")
    assert isinstance(mac, LaunchServicesScheme)
    assert isinstance(scheme_for_platform(root=tmp_path, run=run, platform="sunos"), NoScheme)
    with pytest.raises(AssertionError):  # tests never touch the real handler
        scheme_for_platform()
    cmd = handler_command(tmp_path / "home")
    assert cmd[-3:] == ["--home", str((tmp_path / "home").resolve()), "open-url"]
    assert handler_command()[-1] == "open-url" and "--home" not in handler_command()


def test_handler_command_runs_open_url(tmp_path):
    """The handler command of a developer install is a real command (a
    process; `--help` so that no app starts)."""
    out = subprocess.run(  # noqa: S603 - the test interpreter
        [*handler_command(tmp_path / "h")[:-1], "open-url", "--help"],
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    assert out.returncode == 0 and "anagram://" in out.stdout
