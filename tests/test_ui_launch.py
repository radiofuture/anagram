"""`anagram ui`: the launch link and one UI for each home."""

from __future__ import annotations

import os
import subprocess
import sys
import time


def _ui_process(home, out):
    env = {**os.environ, "ANAGRAM_KEYSTORE": "file", "HF_HUB_OFFLINE": "1"}
    return subprocess.Popen(  # noqa: S603 - this interpreter, fixed arguments
        [sys.executable, "-m", "anagram", "--home", str(home), "ui", "--no-browser"],
        stdout=out,
        stderr=subprocess.STDOUT,
        env=env,
    )


# Only a guard against a hang: the wait ends on a condition (the text, or the
# end of the process), not after a time. A start takes about 1 s.
HANG_GUARD_S = 600.0


def _wait_for(path, text, proc) -> str:
    """Read `path` until it has `text` or the process ended. The state of the
    process is read before the file, so the last read has all its output. A
    read can end in a part of a character; `errors="replace"` keeps it."""
    end = time.monotonic() + HANG_GUARD_S
    while True:
        ended = proc.poll() is not None
        body = path.read_text(errors="replace") if path.exists() else ""
        if text in body or ended or time.monotonic() > end:
            return body
        time.sleep(0.05)


def _stop(proc) -> None:
    proc.terminate()
    try:
        proc.wait(20)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait(5)


def test_ui_link_goes_to_a_redirected_stdout_at_once(tmp_path):
    log = tmp_path / "ui.out"
    with open(log, "w") as out:
        proc = _ui_process(tmp_path / "home", out)
    try:
        body = _wait_for(log, "Open: http://127.0.0.1:", proc)
        assert "Open: http://127.0.0.1:" in body, body
        assert proc.poll() is None  # the UI still runs; the line came before the exit
    finally:
        _stop(proc)


def _port(body: str) -> int:
    line = next(x for x in body.splitlines() if x.startswith("Open: http://127.0.0.1:"))
    return int(line.split("127.0.0.1:", 1)[1].split("/", 1)[0])


def test_one_home_has_one_ui(tmp_path):
    """`anagram open` and a second `anagram ui` find the UI that runs for the
    home; they start no second server."""
    from anagram.shell.app.launcher import LaunchError, live_runtime, open_app

    home = tmp_path / "home"
    log = tmp_path / "ui.out"
    with open(log, "w") as out:
        proc = _ui_process(home, out)
    try:
        port = _port(_wait_for(log, "Open: http://127.0.0.1:", proc))
        doc = live_runtime(home)
        assert doc is not None and doc["port"] == port

        started = []
        try:
            url = open_app(home, start=started.append, browser=lambda u: None, wait_s=2)
        except LaunchError:
            url = ""
        assert started == []
        assert url.startswith(f"http://127.0.0.1:{port}/open/")

        log2 = tmp_path / "ui2.out"
        with open(log2, "w") as out:
            second = _ui_process(home, out)
        try:
            assert second.wait(60) == 0
        finally:
            if second.poll() is None:
                _stop(second)
        body = log2.read_text()
        assert "already runs" in body
        assert _port(body) == port
        assert proc.poll() is None
    finally:
        _stop(proc)
    assert live_runtime(home) is None
