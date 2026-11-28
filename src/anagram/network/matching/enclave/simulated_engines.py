"""The engines of the `simulated` build: the deterministic test embedder and
joint judge (dev and CI).

They prove the plumbing, not the quality of matches. `simulated_engines` is
the `EngineFactory` that the simulated enclave host gives an instance;
`model_descriptors` gives the `model` descriptors of a release that names
them (spec/enclave-trust.md 3.6).
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Iterable
from dataclasses import dataclass

from anagram.core.canonical import JsonObject, canonical_json
from anagram.network.matching.enclave.funnel import Embedder, Engines, JointJudge, Side, Vectors
from anagram.network.matching.trust import descriptor as dsc

FAKE_EMBED_NAME = "anagram-fake-embed-v1"

_WORD = re.compile(r"[a-z0-9]+")
STOPWORDS = frozenset(
    "a an and are as at be by can for from has have in into is it of on or our that the "
    "their this to use using we with who will would need needs offer offers working "
    "help someone people lab labs work".split()
)


def words(text: str) -> list[str]:
    return [w for w in _WORD.findall(text.lower()) if w not in STOPWORDS and len(w) > 2]


@dataclass
class FakeEmbedder(Embedder):
    """Hashed bag of words. Deterministic. It sees words, not meaning: two
    lines with different words for the same thing are far apart."""

    dim: int = 256

    def embed(self, text: str) -> list[int]:
        vec = [0] * self.dim
        for w in words(text):
            h = int.from_bytes(hashlib.sha256(w.encode()).digest()[:4], "big")
            vec[h % self.dim] += 1 if (h >> 31) & 1 else -1
        top = max((abs(v) for v in vec), default=0)
        if top == 0:
            return vec
        return [round(v * 127 / top) for v in vec]


@dataclass
class FakeJointJudge(JointJudge):
    """The deterministic test judge. A side fits when one of its wants is
    near an offer of the other side (cosine at or above `threshold`)."""

    vectors: Vectors
    threshold: float = 0.5
    name: str = "anagram-fake-joint-judge-v1"

    def __post_init__(self) -> None:
        rule = canonical_json({"name": self.name, "threshold": str(self.threshold)})
        self.digest = "sha256:" + hashlib.sha256(rule).hexdigest()

    def _fits(self, me: Side, peer: Side, kind: str) -> bool:
        return any(
            self.vectors.score(w, o) >= self.threshold
            for w in me.wants
            if kind in w["types"]
            for o in peer.offers
            if kind in o["types"]
        )

    def decide(self, first: Side, second: Side, kinds: list[str]) -> JsonObject:
        verdicts = []
        for kind in sorted(kinds):
            fit_a, fit_b = self._fits(first, second, kind), self._fits(second, first, kind)
            verdicts.append((not (fit_a and fit_b), kind, fit_a, fit_b))
        _, kind, fit_a, fit_b = min(verdicts)  # a type where both fit, else the first
        return {
            "fit_a": "fit" if fit_a else "pass",
            "fit_b": "fit" if fit_b else "pass",
            "type": kind,
        }


def fake_embedder_digest() -> str:
    return "sha256:" + hashlib.sha256(FAKE_EMBED_NAME.encode()).hexdigest()


def fake_engines() -> Engines:
    vectors = Vectors(FakeEmbedder())
    return Engines(vectors, FakeJointJudge(vectors))


def model_descriptors() -> list[JsonObject]:
    """The `model` descriptors of a release that runs the test engines."""
    judge = fake_engines().judge
    return [
        {
            "body": {"digest": fake_embedder_digest(), "name": FAKE_EMBED_NAME, "role": "embed"},
            "kind": "model",
            "schema": dsc.SCHEMA,
        },
        {
            "body": {"digest": judge.digest, "name": judge.name, "role": "judge"},
            "kind": "model",
            "schema": dsc.SCHEMA,
        },
    ]


def simulated_engines(models: Iterable[JsonObject]) -> Engines:
    """The `EngineFactory` of the simulated build: the test engines, when
    the release's `model` descriptors name them with their digests."""
    by_role = {d["body"]["role"]: d["body"] for d in models}
    embed = by_role.get("embed")
    if embed is None or embed["name"] != FAKE_EMBED_NAME:
        raise ValueError("the release names no embedding model that this build runs")
    if embed["digest"] != fake_embedder_digest():
        raise ValueError("embedding model digest differs from the descriptor")
    engines = fake_engines()
    judge_body = by_role.get("judge")
    if judge_body is None or judge_body["name"] != engines.judge.name:
        raise ValueError("the release names no judge that this build runs")
    if judge_body["digest"] != engines.judge.digest:
        raise ValueError("judge digest differs from the descriptor")
    return engines
