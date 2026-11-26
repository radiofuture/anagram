"""Local text embeddings for vector search (spec/index.md section 6).

`FastEmbedder` uses fastembed (ONNX Runtime, no torch) on this computer. The
model is downloaded once, on the first call that needs it, into
`<home>/models/`. The download sends no user data: it is a public model file.
Text never leaves the device.

`FakeEmbedder` is deterministic and needs no model. Tests use it. No test
downloads a model.
"""

from __future__ import annotations

import hashlib
import math
import re
from abc import ABC, abstractmethod
from collections.abc import Sequence
from pathlib import Path
from typing import ClassVar

DEFAULT_MODEL = "BAAI/bge-small-en-v1.5"
DEFAULT_DIM = 384
_WORD = re.compile(r"[a-z0-9]+")


class EmbedderError(Exception):
    pass


class Embedder(ABC):
    name: ClassVar[str] = ""
    dim: int = 0

    @abstractmethod
    def embed(self, texts: Sequence[str]) -> list[list[float]]:
        """One unit vector for each text."""

    def ident(self) -> str:
        """Model name and size: vectors of different idents never mix."""
        return f"{self.name}:{self.dim}"

    @property
    def model_id(self) -> str:
        """The model name that a descriptor uses for this embedder."""
        return self.ident()


class FakeEmbedder(Embedder):
    """Hashed bag of words (lower case), normalised. Texts that share words are
    near. Deterministic and offline."""

    name = "fake"

    def __init__(self, dim: int = 64) -> None:
        self.dim = dim
        self.calls = 0

    def embed(self, texts: Sequence[str]) -> list[list[float]]:
        self.calls += 1
        out = []
        for t in texts:
            v = [0.0] * self.dim
            for w in _WORD.findall(t.lower()):
                h = hashlib.sha256(w.encode()).digest()
                v[int.from_bytes(h[:4], "big") % self.dim] += 1.0 if h[4] & 1 else -1.0
            n = math.sqrt(sum(x * x for x in v)) or 1.0
            out.append([x / n for x in v])
        return out


class FastEmbedder(Embedder):
    """fastembed `TextEmbedding`, loaded on first use."""

    name = "fastembed"

    def __init__(
        self, model: str = DEFAULT_MODEL, dim: int = DEFAULT_DIM, cache_dir: Path | None = None
    ) -> None:
        self.model = model
        self.dim = dim
        self.cache_dir = cache_dir
        self._engine = None

    def ident(self) -> str:
        return f"fastembed:{self.model}:{self.dim}"

    @property
    def model_id(self) -> str:
        return self.model

    def _load(self):
        if self._engine is None:
            try:
                from fastembed import TextEmbedding
            except ImportError as exc:
                raise EmbedderError("fastembed is not installed") from exc
            kw = {"cache_dir": str(self.cache_dir)} if self.cache_dir else {}
            try:
                self._engine = TextEmbedding(model_name=self.model, **kw)
            except Exception as exc:  # download or load failure
                raise EmbedderError(f"cannot load {self.model}: {exc}") from exc
        return self._engine

    def embed(self, texts: Sequence[str]) -> list[list[float]]:
        engine = self._load()
        out = []
        for vec in engine.embed(list(texts)):
            v = [float(x) for x in vec]
            if len(v) != self.dim:
                raise EmbedderError(f"{self.model} gives {len(v)} values, not {self.dim}")
            out.append(v)
        return out
