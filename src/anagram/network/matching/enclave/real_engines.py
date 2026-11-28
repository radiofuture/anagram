"""Real matching engines for the enclave (`anagram_pack_match.v1`):

- `fingerprint_model_path`: deterministic SHA-256 over a local model weight file
  or directory manifest inside the sealed image (rejecting missing/empty paths
  and symlinks escaping the root).
- `check_local_judge_url`: strictly enforces loopback-only `http://127.0.0.1`,
  `http://[::1]`, or `http://localhost` (no external hosts, no `https://`, no
  URL credentials) so enclave lines can never leave the sealed machine.
- `OnnxEmbedder`: semantic stage-1 embeddings via offline `FastEmbedder`
  (`local_files_only=True`, `HF_HUB_OFFLINE=1`, SHA-256 weight fingerprinting),
  incorporating `[line["class"]]` context and peak-normalized `int8`
  quantization (`-127..127`).
- `LlmJointJudge`: stage-2 binary `"20-minute coffeehouse"` joint judge running
  either in-process (injectable `complete_fn` or local `llama_cpp` weights) or
  against a loopback-only local OpenAI-compatible daemon inside the same
  confidential VM (`follow_redirects=False`, `trust_env=False`, no API keys),
  with greedy decoding (`temperature=0`), strict enum-only JSON parsing,
  SHA-256 weight fingerprinting, and fail-closed error handling.
- `real_engines(...)`: `EngineFactory` returning `(Vectors(OnnxEmbedder), LlmJointJudge)`
  with stage-1 `min_score` noise filtering and strict release descriptor checks.
- `engines_from_env(...)`: host helper that keeps `simulated_engines` as the
  default and opts into `real_engines` when `ANAGRAM_ENCLAVE_ENGINE=real`.
"""

from __future__ import annotations

import hashlib
import importlib
import json
import math
import os
import re
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlsplit

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
_LOOPBACK_HOSTS = frozenset({"127.0.0.1", "::1", "localhost"})
_LOOPBACK_ERR = "judge must run inside the enclave on loopback only (127.0.0.1 / ::1 / localhost)"
_CHUNK_BYTES = 65536

type EmbedFn = Callable[[Sequence[str]], list[list[float]]]
type CompleteFn = Callable[[str, str], str]


def check_local_judge_url(url: str) -> str:
    """Validate that a local inference daemon URL points strictly to loopback
    HTTP (`http://127.0.0.1[:port]`, `http://[::1][:port]`, or
    `http://localhost[:port]`) with no userinfo, query, or fragment."""
    raw = url.strip()
    if not raw:
        raise ValueError(_LOOPBACK_ERR)
    parsed = urlsplit(raw)
    if parsed.scheme.lower() != "http":
        raise ValueError(_LOOPBACK_ERR)
    if (
        parsed.username is not None
        or parsed.password is not None
        or "@" in parsed.netloc
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError(_LOOPBACK_ERR)
    try:
        _ = parsed.port
    except ValueError as exc:
        raise ValueError(_LOOPBACK_ERR) from exc
    host = (parsed.hostname or "").lower()
    if host not in _LOOPBACK_HOSTS:
        raise ValueError(_LOOPBACK_ERR)
    return raw.rstrip("/")


def _sha256_file(path: Path) -> tuple[str, int]:
    digest = hashlib.sha256()
    total = 0
    with path.open("rb") as fh:
        while chunk := fh.read(_CHUNK_BYTES):
            digest.update(chunk)
            total += len(chunk)
    return digest.hexdigest(), total


def _walk_model_dir(root: Path) -> list[tuple[str, str, int]]:
    entries: list[tuple[str, str, int]] = []
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames.sort()
        filenames.sort()
        base = Path(dirpath)
        for name in dirnames:
            candidate = base / name
            if candidate.is_symlink():
                try:
                    resolved = candidate.resolve(strict=True)
                except OSError as exc:
                    raise ValueError(f"broken symlink in model directory: {candidate}") from exc
                if not resolved.is_relative_to(root):
                    raise ValueError(f"model directory symlink escapes root: {candidate}")
        for name in filenames:
            candidate = base / name
            if candidate.is_symlink():
                try:
                    resolved = candidate.resolve(strict=True)
                except OSError as exc:
                    raise ValueError(f"broken symlink in model directory: {candidate}") from exc
                if not resolved.is_relative_to(root):
                    raise ValueError(f"model directory symlink escapes root: {candidate}")
                target = resolved
            else:
                target = candidate
            if not target.is_file():
                continue
            file_hash, size = _sha256_file(target)
            rel = candidate.relative_to(root).as_posix()
            entries.append((rel, file_hash, size))
    entries.sort(key=lambda item: item[0])
    return entries


def fingerprint_model_path(path: Path) -> str:
    """Compute a deterministic canonical `sha256:<hex>` fingerprint over a
    local model weight file or directory inside the sealed image."""
    target = Path(path)
    if not target.exists():
        raise ValueError(f"model path does not exist: {target}")
    if target.is_file():
        file_hash, size = _sha256_file(target)
        if size == 0:
            raise ValueError(f"model weight file is empty: {target}")
        return f"sha256:{file_hash}"
    if target.is_dir():
        root = target.resolve(strict=True)
        entries = _walk_model_dir(root)
        if not entries or sum(size for _, _, size in entries) == 0:
            raise ValueError(f"model directory contains no non-empty weight files: {target}")
        manifest = canonical_json(
            {"files": [{"path": rel, "sha256": file_hash} for rel, file_hash, _ in entries]}
        )
        return "sha256:" + hashlib.sha256(manifest).hexdigest()
    raise ValueError(f"model path must be a regular file or directory: {target}")


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
    """Semantic stage-1 embedder backed by offline `FastEmbedder` (ONNX Runtime)
    or an injectable `embed_fn` for offline tests."""

    model: str = DEFAULT_EMBED_MODEL
    dim: int = DEFAULT_EMBED_DIM
    model_path: Path | None = None
    cache_dir: Path | None = None
    embed_fn: EmbedFn | None = None
    name: str = field(init=False)
    weights_sha256: str | None = field(init=False)
    digest: str = field(init=False)
    _backend: FastEmbedder | None = field(default=None, init=False, repr=False)

    def __post_init__(self) -> None:
        if self.embed_fn is None and self.model_path is None:
            raise ValueError("OnnxEmbedder requires model_path pointing to local model weights")
        self.name = self.model
        self.weights_sha256 = (
            fingerprint_model_path(self.model_path) if self.model_path is not None else None
        )
        meta = canonical_json(
            {
                "dim": self.dim,
                "model": self.model,
                "quant": "int8-peak",
                "weights_sha256": self.weights_sha256,
            }
        )
        self.digest = "sha256:" + hashlib.sha256(meta).hexdigest()

    def _raw_embed(self, texts: Sequence[str]) -> list[list[float]]:
        if self.embed_fn is not None:
            return self.embed_fn(texts)
        if self._backend is None:
            offline_flag = os.environ.get("HF_HUB_OFFLINE", "").strip().lower()
            if offline_flag and offline_flag not in ("1", "true", "yes"):
                raise ValueError(
                    "enclave embedder requires offline mode (HF_HUB_OFFLINE=1); downloads disabled"
                )
            os.environ.setdefault("HF_HUB_OFFLINE", "1")
            resolved_cache = self.cache_dir
            if resolved_cache is None and self.model_path is not None:
                resolved_cache = (
                    self.model_path if self.model_path.is_dir() else self.model_path.parent
                )
            self._backend = FastEmbedder(
                model=self.model,
                dim=self.dim,
                cache_dir=resolved_cache,
                local_files_only=True,
            )
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


def _extract_choice_content(body: object) -> object:
    choices = body.get("choices") if isinstance(body, dict) else None
    if not isinstance(choices, list) or not choices:
        return None
    first_choice = choices[0]
    message = first_choice.get("message") if isinstance(first_choice, dict) else None
    return message.get("content") if isinstance(message, dict) else None


@dataclass
class LlmJointJudge(JointJudge):
    """Deterministic in-enclave joint judge.

    Runs either in-process (via `complete_fn` or a local `llama_cpp` model file)
    or against a loopback-only local OpenAI-compatible daemon inside the same
    confidential VM (`http://127.0.0.1`, `http://[::1]`, or `http://localhost`,
    with `follow_redirects=False`, `trust_env=False`, and zero external API
    keys). Uses greedy decoding (`temperature=0`), strict JSON enum validation,
    and fails closed (`pass`/`pass`) on any error.
    """

    model: str
    model_path: Path | None = None
    base_url: str | None = None
    complete_fn: CompleteFn | None = None
    timeout: float = DEFAULT_TIMEOUT
    transport: httpx.BaseTransport | None = None
    name: str = ""
    weights_sha256: str | None = field(default=None, init=False)
    digest: str = ""
    _client: httpx.Client | None = field(default=None, init=False, repr=False)
    _local_llm: object | None = field(default=None, init=False, repr=False)

    def __post_init__(self) -> None:
        if self.base_url is not None and self.complete_fn is not None:
            raise ValueError("specify either base_url or complete_fn, not both")
        if self.base_url is not None:
            self.base_url = check_local_judge_url(self.base_url)
        if self.model_path is None and self.complete_fn is None and self.transport is None:
            raise ValueError("LlmJointJudge requires model_path pointing to local model weights")
        if self.model_path is not None:
            self.weights_sha256 = fingerprint_model_path(self.model_path)
        if not self.name:
            self.name = f"anagram-llm-judge-v1:{self.model}"
        if not self.digest:
            meta = canonical_json(
                {
                    "model": self.model,
                    "name": self.name,
                    "prompt": JUDGE_SYSTEM_PROMPT,
                    "prompt_version": JUDGE_PROMPT_VERSION,
                    "weights_sha256": self.weights_sha256,
                }
            )
            self.digest = "sha256:" + hashlib.sha256(meta).hexdigest()

    def _endpoint(self) -> str:
        if self.base_url is None:
            raise ValueError("base_url is not configured")
        base = self.base_url.rstrip("/")
        return f"{base}/chat/completions" if base.endswith("/v1") else f"{base}/v1/chat/completions"

    def _http(self) -> httpx.Client:
        if self._client is None:
            self._client = httpx.Client(
                headers={"Content-Type": "application/json"},
                timeout=self.timeout,
                transport=self.transport,
                follow_redirects=False,
                trust_env=False,
            )
        return self._client

    def close(self) -> None:
        if self._client is not None:
            self._client.close()
            self._client = None
        self._local_llm = None

    def _decide_local_runtime(self, user_prompt: str) -> object:
        if self.model_path is None or not self.model_path.is_file():
            raise ValueError("in-process judge runtime requires a local GGUF model file")
        if self._local_llm is None:
            llama_mod = importlib.import_module("llama_cpp")
            self._local_llm = llama_mod.Llama(model_path=str(self.model_path), verbose=False)
        completion_fn = getattr(self._local_llm, "create_chat_completion", None)
        if not callable(completion_fn):
            raise TypeError("local judge runtime lacks create_chat_completion")
        body = completion_fn(
            messages=[
                {"content": JUDGE_SYSTEM_PROMPT, "role": "system"},
                {"content": user_prompt, "role": "user"},
            ],
            response_format={"type": "json_object"},
            temperature=0.0,
        )
        return _extract_choice_content(body)

    def decide(self, first: Side, second: Side, kinds: list[str]) -> JsonObject:
        if not kinds:
            return _fail_closed(kinds)
        user_prompt = build_judge_prompt(first, second, kinds)
        if self.complete_fn is not None:
            try:
                content: object = self.complete_fn(JUDGE_SYSTEM_PROMPT, user_prompt)
            except (RuntimeError, ValueError, OSError, TypeError, KeyError):
                return _fail_closed(kinds)
            return parse_judge_reply(content, kinds)
        if self.base_url is None:
            try:
                content = self._decide_local_runtime(user_prompt)
            except (ImportError, RuntimeError, ValueError, OSError, TypeError, KeyError):
                return _fail_closed(kinds)
            return parse_judge_reply(content, kinds)
        payload: JsonObject = {
            "messages": [
                {"content": JUDGE_SYSTEM_PROMPT, "role": "system"},
                {"content": user_prompt, "role": "user"},
            ],
            "model": self.model,
            "response_format": {"type": "json_object"},
            "temperature": 0,
        }
        try:
            response = self._http().post(self._endpoint(), json=payload)
            response.raise_for_status()
            content = _extract_choice_content(response.json())
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
    judge_model: str,
    *,
    judge_url: str | None = None,
    judge_model_path: Path | None = None,
    judge_complete_fn: CompleteFn | None = None,
    embed_model: str = DEFAULT_EMBED_MODEL,
    embed_dim: int = DEFAULT_EMBED_DIM,
    embed_model_path: Path | None = None,
    embed_cache_dir: Path | None = None,
    embed_fn: EmbedFn | None = None,
    judge_transport: httpx.BaseTransport | None = None,
    judge_timeout: float = DEFAULT_TIMEOUT,
    min_score: float = DEFAULT_MIN_SCORE,
    strict_descriptors: bool = True,
) -> EngineFactory:
    """Build an `EngineFactory` backed by `OnnxEmbedder` and `LlmJointJudge`."""
    validated_url = check_local_judge_url(judge_url) if judge_url is not None else None
    if embed_fn is None and embed_model_path is None:
        raise ValueError("real_engines requires embed_model_path pointing to local model weights")
    if judge_complete_fn is None and judge_transport is None and judge_model_path is None:
        raise ValueError("real_engines requires judge_model_path pointing to local model weights")

    def factory(models: Iterable[JsonObject]) -> Engines:
        embedder = OnnxEmbedder(
            model=embed_model,
            dim=embed_dim,
            model_path=embed_model_path,
            cache_dir=embed_cache_dir,
            embed_fn=embed_fn,
        )
        judge = LlmJointJudge(
            model=judge_model,
            model_path=judge_model_path,
            base_url=validated_url,
            complete_fn=judge_complete_fn,
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

    Defaults to `simulated_engines`. Opt in to real in-enclave semantic/LLM
    engines with `ANAGRAM_ENCLAVE_ENGINE=real`, `ANAGRAM_ENCLAVE_JUDGE_MODEL`,
    `ANAGRAM_ENCLAVE_EMBED_MODEL_PATH`, and `ANAGRAM_ENCLAVE_JUDGE_MODEL_PATH`
    (plus optional loopback-only `ANAGRAM_ENCLAVE_JUDGE_URL`; omit to run the
    local judge weights in-process).
    """
    source = os.environ if env is None else env
    mode = source.get("ANAGRAM_ENCLAVE_ENGINE", "simulated").strip().lower()
    if mode in ("", "simulated"):
        return simulated_engines
    if mode != "real":
        raise ValueError(f"unknown ANAGRAM_ENCLAVE_ENGINE mode: {mode!r}")
    judge_model = source.get("ANAGRAM_ENCLAVE_JUDGE_MODEL", "").strip()
    embed_path_raw = source.get("ANAGRAM_ENCLAVE_EMBED_MODEL_PATH", "").strip()
    judge_path_raw = source.get("ANAGRAM_ENCLAVE_JUDGE_MODEL_PATH", "").strip()
    if not judge_model or not embed_path_raw or not judge_path_raw:
        raise ValueError(
            "ANAGRAM_ENCLAVE_ENGINE=real requires ANAGRAM_ENCLAVE_JUDGE_MODEL, "
            "ANAGRAM_ENCLAVE_EMBED_MODEL_PATH, and ANAGRAM_ENCLAVE_JUDGE_MODEL_PATH"
        )
    embed_model_path = Path(embed_path_raw)
    judge_model_path = Path(judge_path_raw)
    # Fail closed immediately on missing/empty/escaping model weight files.
    fingerprint_model_path(embed_model_path)
    fingerprint_model_path(judge_model_path)
    judge_url_raw = source.get("ANAGRAM_ENCLAVE_JUDGE_URL", "").strip()
    judge_url = check_local_judge_url(judge_url_raw) if judge_url_raw else None
    embed_model = source.get("ANAGRAM_ENCLAVE_EMBED_MODEL", DEFAULT_EMBED_MODEL).strip()
    cache_raw = source.get("ANAGRAM_ENCLAVE_EMBED_CACHE_DIR", "").strip()
    min_raw = source.get("ANAGRAM_ENCLAVE_MIN_SCORE", "").strip()
    min_score = float(min_raw) if min_raw else DEFAULT_MIN_SCORE
    return real_engines(
        judge_model=judge_model,
        judge_url=judge_url,
        judge_model_path=judge_model_path,
        embed_model=embed_model or DEFAULT_EMBED_MODEL,
        embed_model_path=embed_model_path,
        embed_cache_dir=Path(cache_raw) if cache_raw else None,
        min_score=min_score,
    )
