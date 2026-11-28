"""Offline unit and end-to-end tests for real enclave matching engines
(`OnnxEmbedder`, `LlmJointJudge`, `real_engines`, `engines_from_env`),
loopback-only enforcement, SHA-256 weight fingerprinting, stage-1
`min_score` + `[class]` context, and `Matching._member` kind handling."""

from __future__ import annotations

import copy
import json
import math
import secrets
from collections.abc import Sequence
from pathlib import Path
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
    check_local_judge_url,
    engines_from_env,
    fingerprint_model_path,
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


def _make_weights(tmp_path: Path) -> tuple[Path, Path]:
    embed_dir = tmp_path / "embed-weights"
    embed_dir.mkdir()
    (embed_dir / "model.onnx").write_bytes(b"fake-onnx-weights-v1")
    (embed_dir / "tokenizer.json").write_bytes(b'{"version":"1.0"}')
    judge_file = tmp_path / "judge.gguf"
    judge_file.write_bytes(b"fake-gguf-weights-v1")
    return embed_dir, judge_file


# ---- Loopback-only judge URL & client hardening ----------------------------


@pytest.mark.parametrize(
    "good_url",
    [
        "http://127.0.0.1",
        "http://127.0.0.1:8000",
        "http://127.0.0.1:8000/v1",
        "http://[::1]:8000",
        "http://localhost:11434",
        "http://localhost:11434/v1/",
    ],
)
def test_check_local_judge_url_accepts_loopback_http(good_url: str) -> None:
    assert check_local_judge_url(good_url) == good_url.rstrip("/")


@pytest.mark.parametrize(
    "bad_url",
    [
        "",
        "https://api.openai.com/v1",
        "http://10.0.0.5:8000",
        "http://judge.example.org",
        "http://judge.local",
        "http://user:pass@127.0.0.1:8000",
        "https://127.0.0.1:8000",
        "https://localhost:8000",
        "http://localhost.evil.com:8000",
        "http://127.0.0.1.nip.io:8000",
        "http://127.0.0.2:8000",
        "http://127.0.0.1:8000/v1?redirect=https://evil.example",
        "http://127.0.0.1:8000/v1#frag",
    ],
)
def test_check_local_judge_url_refuses_external_or_unsafe_urls(
    bad_url: str, tmp_path: Path
) -> None:
    _, judge_file = _make_weights(tmp_path)
    with pytest.raises(ValueError, match="loopback only"):
        check_local_judge_url(bad_url)
    with pytest.raises(ValueError, match="loopback only"):
        LlmJointJudge(model="qwen2.5:14b", model_path=judge_file, base_url=bad_url)


def test_llm_judge_http_client_disables_redirects_and_env_proxies(tmp_path: Path) -> None:
    _, judge_file = _make_weights(tmp_path)
    judge = LlmJointJudge(
        model="qwen2.5:14b",
        model_path=judge_file,
        base_url="http://127.0.0.1:8000",
    )
    try:
        client = judge._http()
        assert client.follow_redirects is False
        assert client._trust_env is False
        assert "authorization" not in {k.lower() for k in client.headers}
    finally:
        judge.close()


# ---- SHA-256 weight fingerprinting & strict descriptor verification --------


def test_fingerprint_model_path_rejects_missing_empty_and_escaping_symlinks(
    tmp_path: Path,
) -> None:
    with pytest.raises(ValueError, match="does not exist"):
        fingerprint_model_path(tmp_path / "missing.gguf")

    empty_file = tmp_path / "empty.gguf"
    empty_file.write_bytes(b"")
    with pytest.raises(ValueError, match="empty"):
        fingerprint_model_path(empty_file)

    empty_dir = tmp_path / "empty-dir"
    empty_dir.mkdir()
    with pytest.raises(ValueError, match="no non-empty weight files"):
        fingerprint_model_path(empty_dir)

    outside = tmp_path / "outside.bin"
    outside.write_bytes(b"outside-secret")
    model_dir = tmp_path / "model-dir"
    model_dir.mkdir()
    (model_dir / "escape.onnx").symlink_to(outside)
    with pytest.raises(ValueError, match="symlink escapes root"):
        fingerprint_model_path(model_dir)


def test_weight_file_tampering_changes_digest_and_fails_descriptor_check(tmp_path: Path) -> None:
    embed_dir, judge_file = _make_weights(tmp_path)
    emb = OnnxEmbedder(dim=8, model_path=embed_dir, embed_fn=_semantic_embed)
    judge = LlmJointJudge(
        model="qwen2.5:14b",
        model_path=judge_file,
        complete_fn=lambda _sys, _usr: '{"fit_a": "pass", "fit_b": "pass", "type": "research_fit"}',
    )
    assert emb.weights_sha256 == fingerprint_model_path(embed_dir)
    assert emb.digest == emb.weights_sha256
    assert judge.weights_sha256 == fingerprint_model_path(judge_file)
    assert judge.digest == judge.weights_sha256
    descs = real_model_descriptors(emb, judge)
    assert descs[0]["body"]["digest"] == fingerprint_model_path(embed_dir)
    assert descs[1]["body"]["digest"] == fingerprint_model_path(judge_file)
    factory = real_engines(
        "qwen2.5:14b",
        judge_model_path=judge_file,
        judge_complete_fn=judge.complete_fn,
        embed_dim=8,
        embed_model_path=embed_dir,
        embed_fn=_semantic_embed,
    )
    assert factory(descs).min_score == pytest.approx(0.30)

    # Mutate 1 byte of the embedder weight file -> digest changes and verification fails!
    orig_onnx = (embed_dir / "model.onnx").read_bytes()
    (embed_dir / "model.onnx").write_bytes(orig_onnx[:-1] + b"2")
    assert OnnxEmbedder(dim=8, model_path=embed_dir, embed_fn=_semantic_embed).digest != emb.digest
    with pytest.raises(ValueError, match="embedding model digest"):
        factory(descs)
    (embed_dir / "model.onnx").write_bytes(orig_onnx)

    # Mutate 1 byte of the judge weight file -> digest changes and verification fails!
    orig_gguf = judge_file.read_bytes()
    judge_file.write_bytes(orig_gguf[:-1] + b"2")
    assert (
        LlmJointJudge(
            model="qwen2.5:14b", model_path=judge_file, complete_fn=judge.complete_fn
        ).digest
        != judge.digest
    )
    with pytest.raises(ValueError, match="judge digest"):
        factory(descs)


def test_onnx_embedder_requires_model_dir_and_offline_mode(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    with pytest.raises(ValueError, match="model_path"):
        OnnxEmbedder(dim=8)

    embed_dir, judge_file = _make_weights(tmp_path)
    # Non-directory file path is rejected so fingerprinted & loaded directories cannot diverge.
    with pytest.raises(ValueError, match="directory"):
        OnnxEmbedder(dim=8, model_path=judge_file)

    emb = OnnxEmbedder(dim=8, model_path=embed_dir)
    monkeypatch.setenv("HF_HUB_OFFLINE", "0")
    with pytest.raises(ValueError, match="HF_HUB_OFFLINE=1"):
        emb.embed("Cryo-EM sample prep")

    # Verify FastEmbedder always receives the exact fingerprinted model_path as cache_dir.
    monkeypatch.setenv("HF_HUB_OFFLINE", "1")
    captured_kwargs: dict[str, object] = {}

    class _FakeFastEmbedder:
        def __init__(self, **kwargs: object) -> None:
            captured_kwargs.update(kwargs)

        def embed(self, texts: Sequence[str]) -> list[list[float]]:
            return [[1.0] * 8 for _ in texts]

    monkeypatch.setattr(
        "anagram.network.matching.enclave.real_engines.FastEmbedder", _FakeFastEmbedder
    )
    emb.embed("Cryo-EM sample prep")
    assert captured_kwargs["cache_dir"] == embed_dir
    assert captured_kwargs["local_files_only"] is True


def test_in_process_judge_refuses_to_start_without_llama_cpp_and_runs_when_present(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _, judge_file = _make_weights(tmp_path)
    monkeypatch.setattr("importlib.util.find_spec", lambda _name: None)
    with pytest.raises(RuntimeError, match="llama_cpp"):
        LlmJointJudge(model="local-qwen", model_path=judge_file)

    # When llama_cpp is available, in-process judge directly loads the fingerprinted GGUF file.
    loaded_paths: list[str] = []

    class _FakeLlama:
        def __init__(self, *, model_path: str, verbose: bool) -> None:
            loaded_paths.append(model_path)

        def create_chat_completion(self, **_kwargs: object) -> dict:
            return {
                "choices": [
                    {
                        "message": {
                            "content": '{"fit_a": "fit", "fit_b": "fit", "type": "research_fit"}'
                        }
                    }
                ]
            }

    fake_mod = type("FakeLlamaMod", (), {"Llama": _FakeLlama})()
    monkeypatch.setattr(
        "importlib.util.find_spec", lambda name: object() if name == "llama_cpp" else None
    )
    monkeypatch.setattr(
        "importlib.import_module", lambda name: fake_mod if name == "llama_cpp" else None
    )
    judge = LlmJointJudge(model="local-qwen", model_path=judge_file)
    sa = Side(wants=(_line("w01", "Need cryo-EM"),), offers=())
    sb = Side(wants=(), offers=(_line("o01", "Offer cryo-EM"),))
    assert judge.decide(sa, sb, ["research_fit"]) == {
        "fit_a": "fit",
        "fit_b": "fit",
        "type": "research_fit",
    }
    assert loaded_paths == [str(judge_file)]
    assert judge.stats() == {"decisions": 1, "error_reasons": {}, "errors": 0}


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
            super().__init__(
                model="test-model",
                complete_fn=lambda _s,
                _u: '{"fit_a": "pass", "fit_b": "pass", "type": "research_fit"}',
            )
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


def test_llm_joint_judge_request_shape_and_deterministic_parsing(tmp_path: Path) -> None:
    _, judge_file = _make_weights(tmp_path)
    captured: list[tuple[str, dict, dict]] = []

    def handler(req: httpx.Request) -> httpx.Response:
        captured.append((str(req.url), dict(req.headers), json.loads(req.content)))
        return _chat_response('{"fit_a": "fit", "fit_b": "fit", "type": "method_help"}')

    judge = LlmJointJudge(
        model="qwen2.5:14b",
        model_path=judge_file,
        base_url="http://127.0.0.1:8000",
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
    assert url == "http://127.0.0.1:8000/v1/chat/completions"
    assert "authorization" not in {k.lower() for k in headers}
    assert body["model"] == "qwen2.5:14b"
    assert body["temperature"] == 0
    assert body["response_format"] == {"type": "json_object"}
    assert "vague topical overlap" in body["messages"][0]["content"].lower()
    assert (
        build_judge_prompt(sa, sb, ["method_help", "research_fit"])
        == body["messages"][1]["content"]
    )


def test_llm_joint_judge_in_process_complete_fn_and_fail_closed(tmp_path: Path) -> None:
    _, judge_file = _make_weights(tmp_path)
    sa = Side(wants=(_line("w01", "Need cryo-EM"),), offers=())
    sb = Side(wants=(), offers=(_line("o01", "Offer cryo-EM"),))

    ok = LlmJointJudge(
        model="local-qwen",
        model_path=judge_file,
        complete_fn=lambda _sys, _usr: '{"fit_a": "fit", "fit_b": "fit", "type": "research_fit"}',
    )
    assert ok.decide(sa, sb, ["research_fit"]) == {
        "fit_a": "fit",
        "fit_b": "fit",
        "type": "research_fit",
    }

    def boom(_sys: str, _usr: str) -> str:
        raise RuntimeError("local inference crashed")

    failing = LlmJointJudge(model="local-qwen", model_path=judge_file, complete_fn=boom)
    assert failing.decide(sa, sb, ["method_help", "research_fit"]) == {
        "fit_a": "pass",
        "fit_b": "pass",
        "type": "method_help",
    }


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


def test_llm_joint_judge_fails_closed_and_counts_errors_without_leaking_text(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    _, judge_file = _make_weights(tmp_path)
    canary_line = "PRIVATE_PROTEIN_CANARY_99123"

    def boom(req: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout("timed out", request=req)

    judge = LlmJointJudge(
        model="llama3.1:8b",
        model_path=judge_file,
        base_url="http://127.0.0.1:8000/v1",
        transport=httpx.MockTransport(boom),
    )
    side = Side(wants=(_line("w01", canary_line),), offers=())
    with caplog.at_level("WARNING"):
        try:
            assert judge.decide(side, side, ["method_help", "research_fit"]) == {
                "fit_a": "pass",
                "fit_b": "pass",
                "type": "method_help",
            }
        finally:
            judge.close()
    assert judge.stats() == {
        "decisions": 1,
        "error_reasons": {"http_error": 1},
        "errors": 1,
    }
    assert canary_line not in caplog.text

    # Malformed reply is also counted as invalid_reply (distinct from genuine pass).
    bad_reply = LlmJointJudge(
        model="local-qwen",
        model_path=judge_file,
        complete_fn=lambda _s, _u: "not valid json",
    )
    assert bad_reply.decide(side, side, ["research_fit"]) == {
        "fit_a": "pass",
        "fit_b": "pass",
        "type": "research_fit",
    }
    assert bad_reply.stats() == {
        "decisions": 1,
        "error_reasons": {"invalid_reply": 1},
        "errors": 1,
    }


def test_order_swap_disagreement_drops_pair(tmp_path: Path) -> None:
    embed_dir, judge_file = _make_weights(tmp_path)
    calls = 0

    def asymmetric(req: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        # First order says fit/fit; swapped order says fit/pass -> must disagree and drop!
        if calls % 2 == 1:
            return _chat_response('{"fit_a": "fit", "fit_b": "fit", "type": "research_fit"}')
        return _chat_response('{"fit_a": "fit", "fit_b": "pass", "type": "research_fit"}')

    emb = OnnxEmbedder(dim=8, model_path=embed_dir, embed_fn=_semantic_embed)
    judge = LlmJointJudge(
        model="test",
        model_path=judge_file,
        base_url="http://127.0.0.1:8000",
        transport=httpx.MockTransport(asymmetric),
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


def test_real_engines_descriptor_checks_and_env_opt_in(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    embed_dir, judge_file = _make_weights(tmp_path)
    emb = OnnxEmbedder(dim=8, model_path=embed_dir, embed_fn=_semantic_embed)
    judge = LlmJointJudge(
        model="qwen2.5:14b",
        model_path=judge_file,
        base_url="http://127.0.0.1:8000",
    )
    descs = real_model_descriptors(emb, judge)
    factory = real_engines(
        "qwen2.5:14b",
        judge_url="http://127.0.0.1:8000",
        judge_model_path=judge_file,
        embed_dim=8,
        embed_model_path=embed_dir,
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
    with pytest.raises(ValueError, match="ANAGRAM_ENCLAVE_EMBED_MODEL_PATH"):
        engines_from_env({"ANAGRAM_ENCLAVE_ENGINE": "real"})
    with pytest.raises(ValueError, match="unknown ANAGRAM_ENCLAVE_ENGINE"):
        engines_from_env({"ANAGRAM_ENCLAVE_ENGINE": "bogus"})
    with pytest.raises(ValueError, match="does not exist"):
        engines_from_env(
            {
                "ANAGRAM_ENCLAVE_ENGINE": "real",
                "ANAGRAM_ENCLAVE_JUDGE_MODEL": "qwen2.5:14b",
                "ANAGRAM_ENCLAVE_EMBED_MODEL_PATH": str(tmp_path / "missing-embed"),
                "ANAGRAM_ENCLAVE_JUDGE_MODEL_PATH": str(judge_file),
            }
        )
    with pytest.raises(ValueError, match="loopback only"):
        engines_from_env(
            {
                "ANAGRAM_ENCLAVE_ENGINE": "real",
                "ANAGRAM_ENCLAVE_JUDGE_MODEL": "qwen2.5:14b",
                "ANAGRAM_ENCLAVE_EMBED_MODEL_PATH": str(embed_dir),
                "ANAGRAM_ENCLAVE_JUDGE_MODEL_PATH": str(judge_file),
                "ANAGRAM_ENCLAVE_JUDGE_URL": "https://api.openai.com/v1",
            }
        )
    # Loopback daemon mode
    env_factory = engines_from_env(
        {
            "ANAGRAM_ENCLAVE_ENGINE": "real",
            "ANAGRAM_ENCLAVE_JUDGE_URL": "http://127.0.0.1:8000",
            "ANAGRAM_ENCLAVE_JUDGE_MODEL": "qwen2.5:14b",
            "ANAGRAM_ENCLAVE_EMBED_MODEL_PATH": str(embed_dir),
            "ANAGRAM_ENCLAVE_JUDGE_MODEL_PATH": str(judge_file),
            "ANAGRAM_ENCLAVE_MIN_SCORE": "0.35",
        }
    )
    assert env_factory is not simulated_engines
    # In-process mode refuses to start when llama_cpp is missing, and succeeds when present.
    monkeypatch.setattr("importlib.util.find_spec", lambda _name: None)
    with pytest.raises(RuntimeError, match="llama_cpp"):
        engines_from_env(
            {
                "ANAGRAM_ENCLAVE_ENGINE": "real",
                "ANAGRAM_ENCLAVE_JUDGE_MODEL": "qwen2.5:14b",
                "ANAGRAM_ENCLAVE_EMBED_MODEL_PATH": str(embed_dir),
                "ANAGRAM_ENCLAVE_JUDGE_MODEL_PATH": str(judge_file),
            }
        )
    monkeypatch.setattr(
        "importlib.util.find_spec", lambda name: object() if name == "llama_cpp" else None
    )
    inproc_factory = engines_from_env(
        {
            "ANAGRAM_ENCLAVE_ENGINE": "real",
            "ANAGRAM_ENCLAVE_JUDGE_MODEL": "qwen2.5:14b",
            "ANAGRAM_ENCLAVE_EMBED_MODEL_PATH": str(embed_dir),
            "ANAGRAM_ENCLAVE_JUDGE_MODEL_PATH": str(judge_file),
        }
    )
    assert inproc_factory is not simulated_engines


# ---- End-to-end Matching.sweep() + reveal privacy with real_engines --------


def test_matching_sweep_end_to_end_with_real_engines_and_contact_card_only_reveal(
    tmp_path: Path,
) -> None:
    """Full Matching.sweep() + try_reveal() with `real_engines`:
    - Concrete complementary pair (Alice & Bob) is proposed and revealed;
    - Vague topical overlap pair (Carol & Dave) is rejected (`pass`/`pass`);
    - Asymmetric / one-sided pair (Eve) is rejected;
    - Reveal contains ONLY peer contact card (zero peer lines leaked!);
    - `Matching._member` preserves non-person `kind` from credential facts.
    """
    embed_dir, judge_file = _make_weights(tmp_path)

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

    emb = OnnxEmbedder(dim=8, model_path=embed_dir, embed_fn=_semantic_embed)
    judge = LlmJointJudge(
        model="qwen2.5:14b",
        model_path=judge_file,
        base_url="http://127.0.0.1:8000",
        transport=httpx.MockTransport(mock_judge),
    )
    descs = real_model_descriptors(emb, judge)
    factory = real_engines(
        "qwen2.5:14b",
        judge_url="http://127.0.0.1:8000",
        judge_model_path=judge_file,
        embed_dim=8,
        embed_model_path=embed_dir,
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
