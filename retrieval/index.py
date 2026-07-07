"""Vector index + hybrid retriever for the LINDDUN knowledge base.

- Builds embeddings for all chunks and persists them to storage/index/.
- Retrieval combines dense cosine similarity with a lightweight keyword-overlap
  signal (hybrid), which helps for exact node IDs like "Dd.1.1" that dense
  embeddings can blur. Supports filtering by corpus source.
"""
from __future__ import annotations
import json
import pickle
from dataclasses import dataclass
from pathlib import Path

import numpy as np

import config
from ingestion.loader import Chunk, load_corpus
from retrieval.embeddings import get_backend


INDEX_PATH = config.STORE_DIR / "index.pkl"
META_PATH = config.STORE_DIR / "chunks.json"


@dataclass
class Hit:
    chunk: Chunk
    score: float


class Retriever:
    def __init__(self, chunks: list[Chunk], backend, matrix: np.ndarray):
        self.chunks = chunks
        self.backend = backend
        self.matrix = matrix  # (n_chunks, dim), L2-normalized

    # ---- build / persist ----
    @classmethod
    def build(cls) -> "Retriever":
        chunks = load_corpus()
        backend = get_backend()
        texts = [c.text for c in chunks]
        backend.fit(texts)
        matrix = backend.transform(texts)
        r = cls(chunks, backend, matrix)
        r.save()
        return r

    def save(self):
        with open(INDEX_PATH, "wb") as f:
            pickle.dump({"backend": self.backend, "matrix": self.matrix}, f)
        META_PATH.write_text(json.dumps([c.to_dict() for c in self.chunks], indent=2))

    @classmethod
    def load(cls) -> "Retriever":
        if not INDEX_PATH.exists():
            return cls.build()
        with open(INDEX_PATH, "rb") as f:
            blob = pickle.load(f)
        chunks = [Chunk(**c) for c in json.loads(META_PATH.read_text())]
        return cls(chunks, blob["backend"], blob["matrix"])

    # ---- query ----
    def search(self, query: str, k: int | None = None, source: str | None = None,
               hybrid: bool = True, exclude_kinds: list[str] | None = None) -> list[Hit]:
        k = k or config.TOP_K
        qvec = self.backend.transform([query])[0]
        dense = self.matrix @ qvec  # cosine (all normalized)

        scores = dense.copy()
        if hybrid:
            kw = self._keyword_overlap(query)
            # blend; keyword gets a modest weight, enough to surface exact IDs
            scores = 0.8 * dense + 0.2 * kw

        order = np.argsort(-scores)
        hits: list[Hit] = []
        for idx in order:
            c = self.chunks[idx]
            if source and c.source != source:
                continue
            if exclude_kinds and c.meta.get("kind") in exclude_kinds:
                continue
            hits.append(Hit(chunk=c, score=float(scores[idx])))
            if len(hits) >= k:
                break
        return hits

    def _keyword_overlap(self, query: str) -> np.ndarray:
        q_terms = {t.lower() for t in _tokenize(query)}
        out = np.zeros(len(self.chunks), dtype=np.float32)
        if not q_terms:
            return out
        for i, c in enumerate(self.chunks):
            c_terms = {t.lower() for t in _tokenize(c.text + " " + c.section)}
            if not c_terms:
                continue
            out[i] = len(q_terms & c_terms) / len(q_terms)
        return out


def _tokenize(text: str) -> list[str]:
    import re
    # keep tokens like Dd.1.1, L.2.2.1 intact
    return re.findall(r"[A-Za-z]+\.[0-9.]+[0-9]|[A-Za-z0-9]+", text)


if __name__ == "__main__":
    r = Retriever.build()
    print(f"Indexed {len(r.chunks)} chunks with backend '{r.backend.name}'")
    print(f"Matrix shape: {r.matrix.shape}")
    print(f"Persisted to {config.STORE_DIR}")
