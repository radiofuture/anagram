"""R2 step S13: the end-to-end scenario of `deploy/local_e2e.py` (three
people in two labs: lab space, and a shared finding with a read receipt),
run in process on a test node. The same function runs on the Docker stack.
No model, no network. (Matching runs only in the enclave: the Docker stack
tests it in deploy/enclave_e2e.py, and tests/test_enclave_services.py in
process.)"""

from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest
from sharekit import make_share_net

pytestmark = pytest.mark.usefixtures("no_network")

DEPLOY = Path(__file__).resolve().parents[1] / "deploy" / "local_e2e.py"


def load_e2e():
    spec = importlib.util.spec_from_file_location("anagram_local_e2e", DEPLOY)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_three_people_in_two_labs(tmp_path):
    e2e = load_e2e()
    net = make_share_net(tmp_path)
    work = tmp_path / "work"
    work.mkdir()

    def join(slug, link, orcid, name):
        return net.join(tmp_path / slug, orcid, name, invite=link).client

    lines: list[str] = []
    out = e2e.lab_scenario(net.invite, join, work, log=lines.append)
    assert out == {"labs": 2, "people": 3, "reads": 1}
    assert len(lines) == 4
