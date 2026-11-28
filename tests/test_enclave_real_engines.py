"""Offline unit and end-to-end tests for real enclave matching engines
(`OnnxEmbedder`, `LlmJointJudge`, `real_engines`, `engines_from_env`),
stage-1 `min_score` + `[class]` context, and `Matching._member` kind handling."""

from __future__ import annotations

import copy
import json
import math
import secrets
from collections.abc import Sequence
from typing import cast

import httpx
import pytest

from anagram.network.formats.roster import Network
from anagram.network.formats.strict import DAY
from anagram.network.matching.enclave.funnel import (
    Engines,
    PackMatch,
    Party,
    Rules,
    Side,
    Vectors,
    cosine,
)
from anagram.network.matching.enclave.ledger import Ledger, Subject
from anagram.network.matching.enclave.pairs import Matching
from anagram.network.matching.enclave.real_engines import (
    LlmJointJudge,
    OnnxEmbedder,
    build_judge_prompt,
    engines_from_env,
    format_line_for_embedding,
    parse_judge_reply,
    quantize_int8,
    real_engines,
    real_model_descriptors,
)
from anagram.network.matching.enclave.simulated_engines import simulated_engines

NOW = 1_795_608_000
T = "research_fit"


def _float_cosine(a: Sequence[float], b: Sequence[float]) -> float:
    dot = sum(x * y for x, y in zip(a, b, strict=True))
    na = math.sqrt(sum(x * x for x in a))
    nb = math.sqrt(sum(y * y for y in b))
    return dot / (na * nb) if na and nb else 0.0


def _semantic_embed(texts: Sequence[str]) -> list[list[float]]:
    """Deterministic 8-D semantic basis for offline tests (zero network)."""
    out: list[list[float]] = []
    for raw in texts:
        low = raw.lower()
        v = [0.0] * 8
        # Axis 0: cryo-EM / grid / microscope
        if any(w in low for w in ("cryo", "vitrif", "microscop", "grid")):
            v[0] += 1.0
        # Axis 1: native mass spec / proteomics
        if any(w in low for w in ("mass spec", "proteom", "spectrom")):
            v[1] += 1.0
        # Axis 2: vague cancer / oncology
        if any(w in low for w in ("cancer", "oncolog", "tumor")):
            v[2] += 1.0
        # Axis 3: alpine / pollinator / ecology
        if any(w in low for w in ("alpine", "pollinat", "beetle", "ecolog")):
            v[3] += 1.0
        # Axis 4-5: class signals from `[class]` prefix
        if low.startswith("[instrument]"):
            v[4] += 0.6
        if low.startswith("[data]"):
            v[5] += 0.6
        if low.startswith("[method]"):
            v[6] += 0.3
        if low.startswith("[skill]"):
            v[7] += 0.3
        if all(x == 0.0 for x in v):
            v[7] = 1.0
        out.append(v)
    return out


def _node(label: str) -> dict:
    return {
        "affiliation": f"Institute {label.upper()}",
        "domain": f"inst-{label}.example.org",
        "id": "node-" + label * 32,
        "ror": f"0abcde{label}12",
    }


def _line(lid: str, text: str, cls: str = "method", kinds: list[str] | None = None) -> dict:
    return {
        "class": cls,
        "concepts": [],
        "id": lid,
        "scope": "both",
        "text": text,
        "types": kinds or [T],
    }


def _pack(offer: dict, want: dict, kinds: list[str] | None = None) -> dict:
    protocols = sorted(kinds or [T])
    return {
        "block": {"hide": [], "people": []},
        "charter": {
            "disclosure": "d0",
            "protocols": protocols,
            "rules": dict.fromkeys(protocols, "any"),
            "weekly_cap": 3,
        },
        "deny": {"domains": [], "nodes": [], "rors": []},
        "lines": {"offers": [offer], "wants": [want]},
        "version": 1,
    }


def _party(subject_char: str, node_label: str, pack: dict) -> Party:
    subj = subject_char * 64
    return Party(subj, f"pid:{subject_char * 32}", _node(node_label), pack)


def _facts(p: Party, kind: str = "person") -> dict:
    return {
        "control_head": 0,
        "email_tags": [],
        "expires": NOW + 7 * DAY,
        "issued": NOW - DAY,
        "kind": kind,
        "node": p.node_id,
        "pid": p.pid,
        "token": "AA",
    }


class _StubNet:
    network = "net-" + "0" * 32

    def __init__(self, nodes: list[dict]) -> None:
        self.nodes = {n["id"]: n for n in nodes}
        self.seen_kinds: list[str] = []

    def credential_usable(self, facts: object, raw: bytes) -> None:
        self.seen_kinds.append(str(getattr(facts, "kind", "")))


# ---- quantize_int8 & OnnxEmbedder ------------------------------------------


def test_quantize_int8_preserves_cosine_fidelity_and_bounds() -> None:
    u = [math.sin(i * 0.37) * 0.05 for i in range(384)]
    v = [math.sin(i * 0.37 + 0.5) * 0.05 for i in range(384)]
    w = [math.cos(i * 1.13) * 0.05 for i in range(384)]
    qu, qv, qw = quantize_int8(u), quantize_int8(v), quantize_int8(w)
    for q in (qu, qv, qw):
        assert len(q) == 384
        assert all(-127 <= x <= 127 for x in q)
        assert max(abs(x) for x in q) == 127
    assert cosine(qu, qv) == pytest.approx(_float_cosine(u, v), abs=0.002)
    assert cosine(qu, qw) == pytest.approx(_float_cosine(u, w), abs=0.002)
    assert quantize_int8([0.0, 0.0, 0.0]) == [0, 0, 0]
    assert quantize_int8([float("nan"), float("inf"), 1.0]) == [0, 0, 127]


def test_onnx_embedder_uses_class_context_and_vectors_cache() -> None:
    seen: list[str] = []

    def fake_embed(texts: Sequence[str]) -> list[list[float]]:
        seen.extend(texts)
        return _semantic_embed(texts)

    emb = OnnxEmbedder(dim=8, embed_fn=fake_embed)
    vecs = Vectors(emb)
    inst_line = _line("o01", "Cryo-EM microscope access", cls="instrument")
    data_line = _line("o02", "Cryo-EM microscope access", cls="data")
    assert format_line_for_embedding(inst_line) == "[instrument] Cryo-EM microscope access"
    v_inst = vecs.of_line(inst_line)
    v_data = vecs.of_line(data_line)
    assert v_inst != v_data  # [instrument] vs [data] context changes the vector
    assert seen == [
        "[instrument] Cryo-EM microscope access",
        "[data] Cryo-EM microscope access",
    ]
    # Second lookup hits Vectors cache without calling embed_fn again.
    assert vecs.of_line(inst_line) == v_inst
    assert len(seen) == 2


def test_stage1_min_score_filters_low_similarity_noise() -> None:
    emb = OnnxEmbedder(dim=8, embed_fn=_semantic_embed)
    vecs = Vectors(emb)

    class CountingJudge(LlmJointJudge):
        def __init__(self) -> None:
            super().__init__(base_url="http://judge.local", model="test-model")
            self.calls = 0

        def decide(self, first: Side, second: Side, kinds: list[str]) -> dict:
            self.calls += 1
            return {"fit_a": "pass", "fit_b": "pass", "type": kinds[0]}

    a = _party(
        "a",
        "a",
        _pack(
            _line("o01", "Cryo-EM grid vitrification"), _line("w01", "Cryo-EM grid vitrification")
        ),
    )
    b = _party(
        "b",
        "b",
        _pack(_line("o01", "Alpine pollinator surveys"), _line("w01", "Beetle ecology datasets")),
    )
    parties = {p.subject: p for p in (a, b)}

    # With min_score=0.30, orthogonal cryo-EM vs ecology lines are filtered before Stage-2.
    judge_filtered = CountingJudge()
    match_filtered = PackMatch(Engines(vecs, judge_filtered, min_score=0.30), Rules(1, 1, 3, 7))
    assert match_filtered.stage1(parties, set(parties)) == {}

    # With min_score=0.0 (simulated default), the pair still reaches candidates.
    judge_open = CountingJudge()
    match_open = PackMatch(Engines(vecs, judge_open, min_score=0.0), Rules(1, 1, 3, 7))
    assert match_open.stage1(parties, set(parties)) != {}


# ---- LlmJointJudge ---------------------------------------------------------


def _chat_response(content: str, status: int = 200) -> httpx.Response:
    return httpx.Response(
        status,
        json={"choices": [{"message": {"content": content}}]},
    )


def test_llm_joint_judge_request_shape_and_deterministic_parsing() -> None:
    captured: list[tuple[str, dict, dict]] = []

    def handler(req: httpx.Request) -> httpx.Response:
        captured.append((str(req.url), dict(req.headers), json.loads(req.content)))
        return _chat_response('{"fit_a": "fit", "fit_b": "fit", "type": "method_help"}')

    judge = LlmJointJudge(
        base_url="http://judge.internal:8000",
        model="qwen2.5:14b",
        api_key="enclave-secret",
        transport=httpx.MockTransport(handler),
    )
    sa = Side(
        wants=(_line("w01", "Need native mass spec", cls="method", kinds=["method_help"]),),
        offers=(_line("o01", "Cryo-EM grid prep", cls="method", kinds=["method_help"]),),
    )
    sb = Side(
        wants=(_line("w01", "Need cryo-EM grid prep", cls="method", kinds=["method_help"]),),
        offers=(_line("o01", "Native mass spec", cls="method", kinds=["method_help"]),),
    )
    try:
        out = judge.decide(sa, sb, ["method_help", "research_fit"])
    finally:
        judge.close()

    assert out == {"fit_a": "fit", "fit_b": "fit", "type": "method_help"}
    assert len(captured) == 1
    url, headers, body = captured[0]
    assert url == "http://judge.internal:8000/v1/chat/completions"
    assert headers["authorization"] == "Bearer enclave-secret"
    assert body["model"] == "qwen2.5:14b"
    assert body["temperature"] == 0
    assert body["response_format"] == {"type": "json_object"}
    assert "vague topical overlap" in body["messages"][0]["content"].lower()
    assert (
        build_judge_prompt(sa, sb, ["method_help", "research_fit"])
        == body["messages"][1]["content"]
    )


@pytest.mark.parametrize(
    "raw",
    [
        "not json at all",
        '{"fit_a": "fit", "fit_b": "fit"}',  # missing type
        '{"fit_a": "fit", "fit_b": "fit", "type": "unknown_kind"}',  # unknown kind
        '{"fit_a": "maybe", "fit_b": "fit", "type": "research_fit"}',  # invalid enum
        '{"fit_a": "fit", "fit_b": "fit", "type": "research_fit", "reason": "leaked prose"}',
        "",
    ],
)
def test_parse_judge_reply_fails_closed_on_malformed_or_extra_fields(raw: str) -> None:
    assert parse_judge_reply(raw, ["research_fit", "method_help"]) == {
        "fit_a": "pass",
        "fit_b": "pass",
        "type": "research_fit",
    }


def test_parse_judge_reply_accepts_fenced_json() -> None:
    fenced = '```json\n{"fit_a": "fit", "fit_b": "pass", "type": "method_help"}\n```'
    assert parse_judge_reply(fenced, ["research_fit", "method_help"]) == {
        "fit_a": "fit",
        "fit_b": "pass",
        "type": "method_help",
    }


def test_llm_joint_judge_fails_closed_on_timeout_or_http_error() -> None:
    def boom(req: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout("timed out", request=req)

    judge = LlmJointJudge(
        base_url="http://judge.internal/v1",
        model="llama3.1:8b",
        transport=httpx.MockTransport(boom),
    )
    side = Side(wants=(_line("w01", "Need cryo-EM"),), offers=())
    try:
        assert judge.decide(side, side, ["method_help", "research_fit"]) == {
            "fit_a": "pass",
            "fit_b": "pass",
            "type": "method_help",
        }
    finally:
        judge.close()


def test_order_swap_disagreement_drops_pair() -> None:
    calls = 0

    def asymmetric(req: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        # First order says fit/fit; swapped order says fit/pass -> must disagree and drop!
        if calls % 2 == 1:
            return _chat_response('{"fit_a": "fit", "fit_b": "fit", "type": "research_fit"}')
        return _chat_response('{"fit_a": "fit", "fit_b": "pass", "type": "research_fit"}')

    emb = OnnxEmbedder(dim=8, embed_fn=_semantic_embed)
    judge = LlmJointJudge(
        base_url="http://judge.local", model="test", transport=httpx.MockTransport(asymmetric)
    )
    a = _party("a", "a", _pack(_line("o01", "Cryo-EM grid prep"), _line("w01", "Native mass spec")))
    b = _party("b", "b", _pack(_line("o01", "Native mass spec"), _line("w01", "Cryo-EM grid prep")))
    parties = {p.subject: p for p in (a, b)}
    led = Ledger()
    for p in parties.values():
        led.subjects[p.subject] = Subject(version=1, pack=p.pack, changed=True, reply_key="00" * 32)
    match = PackMatch(Engines(Vectors(emb), judge, min_score=0.30), Rules(1, 1, 3, 7))
    out = match.sweep(led, parties, NOW)
    judge.close()
    assert out.proposals == []
    assert out.disagreements == 1


# ---- real_engines factory & engines_from_env --------------------------------


def test_real_engines_descriptor_checks_and_env_opt_in() -> None:
    emb = OnnxEmbedder(dim=8, embed_fn=_semantic_embed)
    judge = LlmJointJudge(base_url="http://judge.local", model="qwen2.5:14b")
    descs = real_model_descriptors(emb, judge)
    factory = real_engines(
        "http://judge.local",
        "qwen2.5:14b",
        embed_dim=8,
        embed_fn=_semantic_embed,
    )
    built = factory(descs)
    assert built.min_score == pytest.approx(0.30)

    bad = copy.deepcopy(descs)
    bad[1]["body"]["digest"] = "sha256:" + "0" * 64
    with pytest.raises(ValueError, match="judge digest"):
        factory(bad)
    with pytest.raises(ValueError, match="embedding"):
        factory(descs[1:])

    # Default env keeps simulated_engines.
    assert engines_from_env({}) is simulated_engines
    assert engines_from_env({"ANAGRAM_ENCLAVE_ENGINE": "simulated"}) is simulated_engines
    with pytest.raises(ValueError, match="ANAGRAM_ENCLAVE_JUDGE_URL"):
        engines_from_env({"ANAGRAM_ENCLAVE_ENGINE": "real"})
    with pytest.raises(ValueError, match="unknown ANAGRAM_ENCLAVE_ENGINE"):
        engines_from_env({"ANAGRAM_ENCLAVE_ENGINE": "bogus"})
    env_factory = engines_from_env(
        {
            "ANAGRAM_ENCLAVE_ENGINE": "real",
            "ANAGRAM_ENCLAVE_JUDGE_URL": "http://judge.local",
            "ANAGRAM_ENCLAVE_JUDGE_MODEL": "qwen2.5:14b",
            "ANAGRAM_ENCLAVE_MIN_SCORE": "0.35",
        }
    )
    assert env_factory is not simulated_engines


# ---- End-to-end Matching.sweep() + reveal privacy with real_engines --------


def test_matching_sweep_end_to_end_with_real_engines_and_contact_card_only_reveal() -> None:
    """Full Matching.sweep() + try_reveal() with `real_engines`:
    - Concrete complementary pair (Alice & Bob) is proposed and revealed;
    - Vague topical overlap pair (Carol & Dave) is rejected (`pass`/`pass`);
    - Asymmetric / one-sided pair (Eve) is rejected;
    - Reveal contains ONLY peer contact card (zero peer lines leaked!);
    - `Matching._member` preserves non-person `kind` from credential facts.
    """

    def mock_judge(req: httpx.Request) -> httpx.Response:
        user_msg = json.loads(req.content)["messages"][1]["content"].lower()
        # Concrete complementary bridge: cryo-EM <-> native mass spec
        if "cryo-em" in user_msg and "mass spec" in user_msg:
            if "only offers" in user_msg:
                # Asymmetric: person offering cryo-EM wants ecology, so only one side fits.
                side_a_block = user_msg.split("person b:")[0]
                if "only offers" in side_a_block:
                    return _chat_response(
                        '{"fit_a": "pass", "fit_b": "fit", "type": "research_fit"}'
                    )
                return _chat_response('{"fit_a": "fit", "fit_b": "pass", "type": "research_fit"}')
            return _chat_response('{"fit_a": "fit", "fit_b": "fit", "type": "research_fit"}')
        # Vague cancer/oncology overlap -> rejected!
        return _chat_response('{"fit_a": "pass", "fit_b": "pass", "type": "research_fit"}')

    alice = _party(
        "a",
        "a",
        _pack(
            _line("o01", "Cryo-EM grid vitrification for membrane proteins", cls="method"),
            _line("w01", "Native mass spectrometry of intact protein complexes", cls="method"),
        ),
    )
    bob = _party(
        "b",
        "b",
        _pack(
            _line("o01", "Native mass spectrometry of membrane protein complexes", cls="method"),
            _line("w01", "Cryo-EM grid vitrification and screening", cls="method"),
        ),
    )
    carol = _party(
        "c",
        "c",
        _pack(
            _line("o01", "General cancer biology expertise", cls="skill"),
            _line("w01", "Collaborators in cancer research", cls="problem"),
        ),
    )
    dave = _party(
        "d",
        "d",
        _pack(
            _line("o01", "Oncology background and tumor biology", cls="skill"),
            _line("w01", "Oncology discussion partners", cls="problem"),
        ),
    )
    eve = _party(
        "e",
        "e",
        _pack(
            _line("o01", "Only offers cryo-EM grid prep", cls="method"),
            _line("w01", "Alpine pollinator surveys", cls="data"),
        ),
    )
    parties = [alice, bob, carol, dave, eve]

    led = Ledger()
    for p in parties:
        kind = "group" if p is eve else "person"
        led.subjects[p.subject] = Subject(
            version=1,
            pack=p.pack,
            facts=_facts(p, kind=kind),
            changed=True,
            reply_key="00" * 32,
        )

    emb = OnnxEmbedder(dim=8, embed_fn=_semantic_embed)
    judge = LlmJointJudge(
        base_url="http://judge.local",
        model="qwen2.5:14b",
        transport=httpx.MockTransport(mock_judge),
    )
    descs = real_model_descriptors(emb, judge)
    factory = real_engines(
        "http://judge.local",
        "qwen2.5:14b",
        embed_dim=8,
        embed_fn=_semantic_embed,
        judge_transport=httpx.MockTransport(mock_judge),
        min_score=0.30,
    )
    net = _StubNet([p.node for p in parties])
    matching = Matching(
        cast(Network, net),
        PackMatch(factory(descs), Rules(2, 1, 3, 7)),
        lambda: secrets.token_hex(16),
        lambda _: None,
    )
    matching.sweep(led, NOW)

    # Matching._member preserved `kind="group"` for Eve instead of hardcoding "person".
    assert "group" in net.seen_kinds and "person" in net.seen_kinds

    # ONLY Alice & Bob were proposed (Carol/Dave vague overlap and Eve asymmetric were rejected).
    assert len(led.pairs) == 1
    (pair_id, pair) = next(iter(led.pairs.items()))
    assert {pair.a, pair.b} == {alice.subject, bob.subject}

    # Deliver the day's proposal slots before answering.
    led.take_slots(NOW // DAY + 1)

    # Both say yes with contact cards -> mutual reveal exchanges contact card ONLY!
    alice_card = {
        "email": "alice@inst-a.example.org",
        "institution": "Institute A",
        "lab": "Cryo Lab",
        "name": "Alice",
        "orcid": "0000-0001-2345-6789",
    }
    bob_card = {
        "email": "bob@inst-b.example.org",
        "institution": "Institute B",
        "lab": "Mass Spec Lab",
        "name": "Bob",
        "orcid": "0000-0002-3456-7890",
    }
    led.answer(alice.subject, pair.copies[alice.subject], "yes", alice_card, NOW + 60)
    led.answer(bob.subject, pair.copies[bob.subject], "yes", bob_card, NOW + 120)
    matching.try_reveal(led, pair_id, NOW + 180)

    alice_reveal = next(
        entry["item"]
        for entry in led.subjects[alice.subject].queue
        if entry["item"]["kind"] == "reveal"
    )
    bob_reveal = next(
        entry["item"]
        for entry in led.subjects[bob.subject].queue
        if entry["item"]["kind"] == "reveal"
    )
    assert alice_reveal["card"] == bob_card
    assert bob_reveal["card"] == alice_card
    # Strictly verify ZERO peer approved lines leak into reveal items!
    alice_blob = json.dumps(alice_reveal)
    bob_blob = json.dumps(bob_reveal)
    assert "Native mass spectrometry of membrane protein complexes" not in alice_blob
    assert "Cryo-EM grid vitrification and screening" not in alice_blob
    assert "Cryo-EM grid vitrification for membrane proteins" not in bob_blob
    assert "Native mass spectrometry of intact protein complexes" not in bob_blob
    assert set(alice_reveal.keys()) == {"card", "kind", "known", "node", "peer", "proposal", "type"}
