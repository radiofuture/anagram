"""Real matching engines for the enclave (`anagram_pack_match.v1`):

- `OnnxEmbedder`: semantic stage-1 embeddings via `FastEmbedder`
  (`BAAI/bge-small-en-v1.5` by default), incorporating `[line["class"]]`
  context and peak-normalized `int8` quantization (`-127..127`) for high
  cosine fidelity inside `Vectors`.
- `LlmJointJudge`: stage-2 binary `"20-minute coffeehouse"` joint judge
  against any OpenAI-compatible `/v1/chat/completions` endpoint (Ollama,
  vLLM, llama.cpp inside a confidential VM) with greedy decoding
  (`temperature=0`), strict enum-only JSON parsing, and fail-closed error
  handling.
- `real_engines(...)`: `EngineFactory` returning `(Vectors(OnnxEmbedder), LlmJointJudge)`
  with stage-1 `min_score` noise filtering.
- `engines_from_env(...)`: host helper that keeps `simulated_engines` as the
  default and opts into `real_engines` when `ANAGRAM_ENCLAVE_ENGINE=real`.
"""

from __future__ import annotations

import hashlib
import json
import math
import os
import re
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path

import httpx

from anagram.core.canonical import JsonObject, canonical_json
from anagram.models.embed import DEFAULT_DIM as FASTEMBED_DIM
from anagram.models.embed import DEFAULT_MODEL as FASTEMBED_MODEL
from anagram.models.embed import FastEmbedder
from anagram.network.matching.enclave.funnel import (
    Embedder,
    EngineFactory,
    Engines,
    JointJudge,
    Side,
    Vectors,
)
from anagram.network.matching.enclave.simulated_engines import simulated_engines
from anagram.network.matching.trust import descriptor as dsc

DEFAULT_EMBED_MODEL = FASTEMBED_MODEL
DEFAULT_EMBED_DIM = FASTEMBED_DIM
DEFAULT_MIN_SCORE = 0.30
DEFAULT_TIMEOUT = 30.0
JUDGE_PROMPT_VERSION = "coffeehouse.v1"

JUDGE_SYSTEM_PROMPT = (
    "You are the sealed matching judge for a scientific research network.\n"
    "Decide whether Person A and Person B have a specific, concrete, two-way"
    " reason to spend 20 minutes talking over coffee.\n"
    "Rules:\n"
    "- Each person lists what they OFFER and what they WANT, tagged with line class"
    " and allowed match types.\n"
    '- Set `fit_a` to "fit" ONLY if Person B\'s offers or wants directly address a'
    " concrete need, bottleneck, method, dataset, material, instrument, replication,"
    " or supervision request of Person A (or establish a concrete two-way bridge).\n"
    '- Set `fit_b` to "fit" ONLY if Person A\'s offers or wants directly address a'
    " concrete need of Person B.\n"
    '- REJECT vague topical overlap: return "pass" if both people merely work in'
    " the same broad area (for example, both study cancer, both use machine learning,"
    " or both work in genomics) without a concrete complementary bridge.\n"
    '- If only one side benefits, return "pass" for the side that does not.\n'
    "- Choose `type` strictly from the allowed match types listed in the user message.\n"
    "- Return ONLY a single JSON object with exact keys:"
    ' {"fit_a": "fit"|"pass", "fit_b": "fit"|"pass", "type": "<allowed type>"}.'
    " Output no prose, no explanation, and no extra keys."
)

_FENCE = re.compile(r"^```(?:json)?\s*(.*?)\s*```$", re.DOTALL | re.IGNORECASE)
_FIT_VALUES = frozenset({"fit", "pass"})

type EmbedFn = Callable[[Sequence[str]], list[list[float]]]


def quantize_int8(vec: Sequence[float]) -> list[int]:
    """L2-normalize a float vector and quantize to `int8` (`-127..127`) using
    per-vector peak scaling so cosine similarity preserves full 8-bit dynamic
    range."""
    if not vec:
        return []
    clean = [float(x) if math.isfinite(x) else 0.0 for x in vec]
    norm = math.sqrt(sum(x * x for x in clean))
    if norm == 0.0:
        return [0] * len(clean)
    unit = [x / norm for x in clean]
    peak = max(abs(x) for x in unit)
    if peak == 0.0:
        return [0] * len(clean)
    scale = 127.0 / peak
    return [max(-127, min(127, round(x * scale))) for x in unit]


def format_line_for_embedding(line: JsonObject) -> str:
    """Include `[line["class"]]` context when present so embeddings distinguish
    instruments, datasets, materials, methods, and problems."""
    cls = line.get("class")
    text = str(line["text"])
    return f"[{cls}] {text}" if isinstance(cls, str) and cls else text


@dataclass
class OnnxEmbedder(Embedder):
    """Semantic stage-1 embedder backed by `FastEmbedder` (ONNX Runtime) or an
    injectable `embed_fn` for offline tests."""

    model: str = DEFAULT_EMBED_MODEL
    dim: int = DEFAULT_EMBED_DIM
    cache_dir: Path | None = None
    embed_fn: EmbedFn | None = None
    name: str = field(init=False)
    digest: str = field(init=False)
    _backend: FastEmbedder | None = field(default=None, init=False, repr=False)

    def __post_init__(self) -> None:
        self.name = self.model
        meta = canonical_json({"dim": self.dim, "model": self.model, "quant": "int8-peak"})
        self.digest = "sha256:" + hashlib.sha256(meta).hexdigest()

    def _raw_embed(self, texts: Sequence[str]) -> list[list[float]]:
        if self.embed_fn is not None:
            return self.embed_fn(texts)
        if self._backend is None:
            self._backend = FastEmbedder(model=self.model, dim=self.dim, cache_dir=self.cache_dir)
        return self._backend.embed(texts)

    def embed(self, text: str) -> list[int]:
        vectors = self._raw_embed([text])
        if not vectors:
            return [0] * self.dim
        return quantize_int8(vectors[0])

    def embed_line(self, line: JsonObject) -> list[int]:
        return self.embed(format_line_for_embedding(line))


def _format_side(label: str, side: Side) -> str:
    lines = [f"{label}:"]
    lines.append("  Offers:")
    if side.offers:
        for ln in side.offers:
            cls = ln.get("class")
            prefix = f"[{cls}] " if isinstance(cls, str) and cls else ""
            types = ", ".join(str(t) for t in (ln.get("types") or ()))
            lines.append(f"  - {prefix}{ln['text']} (types: {types})")
    else:
        lines.append("  - (none)")
    lines.append("  Wants:")
    if side.wants:
        for ln in side.wants:
            cls = ln.get("class")
            prefix = f"[{cls}] " if isinstance(cls, str) and cls else ""
            types = ", ".join(str(t) for t in (ln.get("types") or ()))
            lines.append(f"  - {prefix}{ln['text']} (types: {types})")
    else:
        lines.append("  - (none)")
    return "\n".join(lines)


def build_judge_prompt(first: Side, second: Side, kinds: Sequence[str]) -> str:
    """Build the deterministic user message for the joint judge."""
    allowed = ", ".join(sorted(kinds))
    return (
        f"Allowed match types: {allowed}\n\n"
        f"{_format_side('Person A', first)}\n\n"
        f"{_format_side('Person B', second)}"
    )


def _fail_closed(kinds: Sequence[str]) -> JsonObject:
    fallback = kinds[0] if kinds else "research_fit"
    return {"fit_a": "pass", "fit_b": "pass", "type": fallback}


def parse_judge_reply(content: object, kinds: Sequence[str]) -> JsonObject:
    """Strictly parse and validate judge JSON output; fail closed on any error."""
    if not isinstance(content, str):
        return _fail_closed(kinds)
    text = content.strip()
    fence = _FENCE.match(text)
    if fence is not None:
        text = fence.group(1).strip()
    try:
        parsed = json.loads(text)
    except ValueError:
        return _fail_closed(kinds)
    if not isinstance(parsed, dict) or set(parsed.keys()) != {"fit_a", "fit_b", "type"}:
        return _fail_closed(kinds)
    fit_a, fit_b, kind = parsed["fit_a"], parsed["fit_b"], parsed["type"]
    if (
        not isinstance(fit_a, str)
        or not isinstance(fit_b, str)
        or not isinstance(kind, str)
        or fit_a not in _FIT_VALUES
        or fit_b not in _FIT_VALUES
        or kind not in kinds
    ):
        return _fail_closed(kinds)
    return {"fit_a": fit_a, "fit_b": fit_b, "type": kind}


@dataclass
class LlmJointJudge(JointJudge):
    """Deterministic OpenAI-compatible `/v1/chat/completions` joint judge.

    Uses greedy decoding (`temperature=0`), strict JSON enum validation, and
    fails closed (`pass`/`pass`) on any transport, timeout, or schema error.
    """

    base_url: str
    model: str
    api_key: str | None = None
    timeout: float = DEFAULT_TIMEOUT
    transport: httpx.BaseTransport | None = None
    name: str = ""
    digest: str = ""
    _client: httpx.Client | None = field(default=None, init=False, repr=False)

    def __post_init__(self) -> None:
        if not self.name:
            self.name = f"anagram-llm-judge-v1:{self.model}"
        if not self.digest:
            meta = canonical_json(
                {
                    "model": self.model,
                    "name": self.name,
                    "prompt": JUDGE_SYSTEM_PROMPT,
                    "prompt_version": JUDGE_PROMPT_VERSION,
                }
            )
            self.digest = "sha256:" + hashlib.sha256(meta).hexdigest()

    def _endpoint(self) -> str:
        base = self.base_url.rstrip("/")
        return f"{base}/chat/completions" if base.endswith("/v1") else f"{base}/v1/chat/completions"

    def _http(self) -> httpx.Client:
        if self._client is None:
            headers = {"Content-Type": "application/json"}
            if self.api_key:
                headers["Authorization"] = f"Bearer {self.api_key}"
            self._client = httpx.Client(
                headers=headers, timeout=self.timeout, transport=self.transport
            )
        return self._client

    def close(self) -> None:
        if self._client is not None:
            self._client.close()
            self._client = None

    def decide(self, first: Side, second: Side, kinds: list[str]) -> JsonObject:
        if not kinds:
            return _fail_closed(kinds)
        payload: JsonObject = {
            "messages": [
                {"content": JUDGE_SYSTEM_PROMPT, "role": "system"},
                {"content": build_judge_prompt(first, second, kinds), "role": "user"},
            ],
            "model": self.model,
            "response_format": {"type": "json_object"},
            "temperature": 0,
        }
        try:
            response = self._http().post(self._endpoint(), json=payload)
            response.raise_for_status()
            body = response.json()
            choices = body.get("choices") if isinstance(body, dict) else None
            if not isinstance(choices, list) or not choices:
                return _fail_closed(kinds)
            message = choices[0].get("message") if isinstance(choices[0], dict) else None
            content = message.get("content") if isinstance(message, dict) else None
        except (httpx.HTTPError, ValueError, KeyError, TypeError):
            return _fail_closed(kinds)
        return parse_judge_reply(content, kinds)


def real_model_descriptors(embedder: OnnxEmbedder, judge: LlmJointJudge) -> list[JsonObject]:
    """The `model` descriptors of a release that runs `embedder` and `judge`."""
    return [
        {
            "body": {"digest": embedder.digest, "name": embedder.name, "role": "embed"},
            "kind": "model",
            "schema": dsc.SCHEMA,
        },
        {
            "body": {"digest": judge.digest, "name": judge.name, "role": "judge"},
            "kind": "model",
            "schema": dsc.SCHEMA,
        },
    ]


def real_engines(  # noqa: PLR0913 - explicit configuration of real embedder and judge
    judge_url: str,
    judge_model: str,
    *,
    embed_model: str = DEFAULT_EMBED_MODEL,
    embed_dim: int = DEFAULT_EMBED_DIM,
    embed_cache_dir: Path | None = None,
    embed_fn: EmbedFn | None = None,
    judge_transport: httpx.BaseTransport | None = None,
    judge_api_key: str | None = None,
    judge_timeout: float = DEFAULT_TIMEOUT,
    min_score: float = DEFAULT_MIN_SCORE,
    strict_descriptors: bool = True,
) -> EngineFactory:
    """Build an `EngineFactory` backed by `OnnxEmbedder` and `LlmJointJudge`."""

    def factory(models: Iterable[JsonObject]) -> Engines:
        embedder = OnnxEmbedder(
            model=embed_model,
            dim=embed_dim,
            cache_dir=embed_cache_dir,
            embed_fn=embed_fn,
        )
        judge = LlmJointJudge(
            base_url=judge_url,
            model=judge_model,
            api_key=judge_api_key,
            timeout=judge_timeout,
            transport=judge_transport,
        )
        if strict_descriptors:
            by_role = {d["body"]["role"]: d["body"] for d in models}
            embed_body = by_role.get("embed")
            if embed_body is None or embed_body["name"] != embedder.name:
                raise ValueError("the release names no embedding model that this build runs")
            if embed_body["digest"] != embedder.digest:
                raise ValueError("embedding model digest differs from the descriptor")
            judge_body = by_role.get("judge")
            if judge_body is None or judge_body["name"] != judge.name:
                raise ValueError("the release names no judge that this build runs")
            if judge_body["digest"] != judge.digest:
                raise ValueError("judge digest differs from the descriptor")
        return Engines(Vectors(embedder), judge, min_score=min_score)

    return factory


def engines_from_env(env: Mapping[str, str] | None = None) -> EngineFactory:
    """Choose the enclave engine factory from environment variables.

    Defaults to `simulated_engines`. Opt in to real semantic/LLM engines with
    `ANAGRAM_ENCLAVE_ENGINE=real` plus `ANAGRAM_ENCLAVE_JUDGE_URL` and
    `ANAGRAM_ENCLAVE_JUDGE_MODEL`.
    """
    source = os.environ if env is None else env
    mode = source.get("ANAGRAM_ENCLAVE_ENGINE", "simulated").strip().lower()
    if mode in ("", "simulated"):
        return simulated_engines
    if mode != "real":
        raise ValueError(f"unknown ANAGRAM_ENCLAVE_ENGINE mode: {mode!r}")
    judge_url = source.get("ANAGRAM_ENCLAVE_JUDGE_URL", "").strip()
    judge_model = source.get("ANAGRAM_ENCLAVE_JUDGE_MODEL", "").strip()
    if not judge_url or not judge_model:
        raise ValueError(
            "ANAGRAM_ENCLAVE_ENGINE=real requires ANAGRAM_ENCLAVE_JUDGE_URL"
            " and ANAGRAM_ENCLAVE_JUDGE_MODEL"
        )
    embed_model = source.get("ANAGRAM_ENCLAVE_EMBED_MODEL", DEFAULT_EMBED_MODEL).strip()
    cache_raw = source.get("ANAGRAM_ENCLAVE_EMBED_CACHE_DIR", "").strip()
    min_raw = source.get("ANAGRAM_ENCLAVE_MIN_SCORE", "").strip()
    min_score = float(min_raw) if min_raw else DEFAULT_MIN_SCORE
    return real_engines(
        judge_url=judge_url,
        judge_model=judge_model,
        embed_model=embed_model or DEFAULT_EMBED_MODEL,
        embed_cache_dir=Path(cache_raw) if cache_raw else None,
        judge_api_key=source.get("ANAGRAM_ENCLAVE_JUDGE_API_KEY") or None,
        min_score=min_score,
    )
