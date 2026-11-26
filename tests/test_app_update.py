"""The update check (R1 plan, section 6.6; step S13): a signed manifest, no
request when the build has no URL, and a new version that makes the
launcher start the new app. No network: the fetch is a fake."""

from __future__ import annotations

import json
import threading

import pytest
from test_app_control import app  # noqa: F401 - fixture

from anagram.core.crypto.signing import SigningKey
from anagram.shell.app import launcher, update
from anagram.shell.app.control import read_runtime
from anagram.shell.app.update import UpdateChecker, UpdateError, check, sign_manifest
from anagram.shell.ui.flows import FLOWS

RELEASE = SigningKey.from_seed(bytes(range(32)))
OTHER = SigningKey.from_seed(bytes(range(1, 33)))
URL = "https://releases.example.org/anagram/manifest.json"


def manifest(version="9.0.0", key=RELEASE, **kw) -> bytes:
    body = {
        "min_os": {"macos": "13.0"},
        "url": {"macos": "https://releases.example.org/Anagram-9.dmg"},
        "version": version,
        **kw,
    }
    return json.dumps(sign_manifest(key, body)).encode()


class Fetch:
    def __init__(self, data: bytes) -> None:
        self.data = data
        self.calls: list[str] = []

    def __call__(self, url: str) -> bytes:
        self.calls.append(url)
        return self.data


def test_good_signature_gives_the_update():
    f = Fetch(manifest())
    out = check(URL, RELEASE.public_bytes().hex(), current="0.1.0", plat="darwin",
                os_version="14.2", fetch=f)  # fmt: skip
    assert out == {
        "available": True,
        "url": "https://releases.example.org/Anagram-9.dmg",
        "version": "9.0.0",
    }
    assert f.calls == [URL]


def test_update_manifest_bad_signature():
    with pytest.raises(UpdateError):
        check(URL, RELEASE.public_bytes(), current="0.1.0", plat="darwin",
              fetch=Fetch(manifest(key=OTHER)))  # fmt: skip
    # A changed field after the signature.
    doc = json.loads(manifest())
    doc["url"]["macos"] = "https://evil.example.org/Anagram.dmg"
    with pytest.raises(UpdateError):
        check(URL, RELEASE.public_bytes(), plat="darwin", fetch=Fetch(json.dumps(doc).encode()))
    for bad in (b"not json", b"[]", json.dumps({**doc, "extra": 1}).encode()):
        with pytest.raises(UpdateError):
            check(URL, RELEASE.public_bytes(), plat="darwin", fetch=Fetch(bad))


def test_signed_http_link_is_refused():
    body = manifest(url={"macos": "http://releases.example.org/Anagram.dmg"})
    with pytest.raises(UpdateError):
        check(URL, RELEASE.public_bytes(), plat="darwin", fetch=Fetch(body))


def test_no_url_means_no_request():
    f = Fetch(manifest())
    assert check(None, RELEASE.public_bytes(), fetch=f) == update.NO_UPDATE
    assert check(URL, None, fetch=f) == update.NO_UPDATE
    assert f.calls == []
    # The build constants are empty: the checker of the runtime is off.
    assert update.MANIFEST_URL is None and update.RELEASE_KEY is None
    c = UpdateChecker(fetch=f)
    assert not c.enabled
    c.tick()
    assert f.calls == [] and c.status() == update.NO_UPDATE


def test_same_version_old_os_or_other_platform_is_no_update():
    key = RELEASE.public_bytes()
    assert check(URL, key, current="9.0.0", plat="darwin", fetch=Fetch(manifest()))[
        "available"
    ] is False  # fmt: skip
    assert not check(URL, key, current="0.1.0", plat="darwin", os_version="12.7",
                     fetch=Fetch(manifest()))["available"]  # fmt: skip
    assert not check(URL, key, current="0.1.0", plat="linux", fetch=Fetch(manifest()))["available"]


def test_https_fetch_refuses_plain_http():
    with pytest.raises(UpdateError):
        update.https_fetch("http://releases.example.org/manifest.json")


def test_checker_checks_one_time_each_day_and_reports_changes():
    now = [1000.0]
    seen = []
    f = Fetch(manifest())
    c = UpdateChecker(URL, RELEASE.public_bytes().hex(), fetch=f, on_change=seen.append,
                      clock=lambda: now[0])  # fmt: skip
    c.tick()
    c.tick()
    assert len(f.calls) == 1 and c.status()["available"] and len(seen) == 1
    now[0] += update.CHECK_EVERY_S
    f.data = manifest(key=OTHER)  # a bad manifest keeps the last result
    c.tick()
    assert len(f.calls) == 2 and c.status()["available"] and len(seen) == 1


def test_flow_entry():
    (flow,) = [f for f in FLOWS if f["id"] == "update-check"]
    assert set(flow) == {"id", "to", "what", "when", "can_see"}
    assert "IP address" in flow["can_see"]


def test_runtime_update_status_and_api(tmp_path, app):  # noqa: F811
    rt = app(tmp_path / "h")
    assert rt.update_status() == update.NO_UPDATE
    assert "app.update" not in rt.ctx.tasks.names()  # no URL: no task


def test_new_version_makes_the_launcher_start_the_new_app(tmp_path, app):  # noqa: F811
    home = tmp_path / "h"
    old = app(home)
    old.version = "0.0.1"  # the app that runs is older than this program
    from anagram.shell.app import control

    control.write_runtime(home, control.runtime_doc(old))
    t = threading.Thread(target=old.run_forever, daemon=True)
    t.start()
    started = []
    launcher.open_app(home, start=lambda h: started.append(app(h)), browser=lambda u: None,
                      wait_s=10)  # fmt: skip
    t.join(10)
    assert not t.is_alive()  # the old app stopped
    assert len(started) == 1
    assert read_runtime(home)["instance"] == started[0].instance
