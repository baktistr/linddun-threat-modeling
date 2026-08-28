"""Vector index + hybrid retriever for the LINDDUN knowledge base.

- Builds document-side vectors for all chunks and persists them to storage/index/.
- Retrieval combines the backend's own similarity with a lightweight
  keyword-overlap signal (hybrid), which helps for exact node IDs like "Dd.1.1"
  that a backend's own weighting can blur. Supports filtering by corpus source.
- Each backend persists to its own index file, so tfidf / bm25 / sbert indexes
  can coexist and be switched between with EMBEDDING_BACKEND without rebuilding.
- The chunk list lives inside each index file, not in a shared sidecar: the matrix
  rows and the chunks they name are one artifact, and a corpus that has grown since
  a matrix was built must never be able to re-label that matrix's rows.
"""
from __future__ import annotations
import json
import pickle
from dataclasses import dataclass
from pathlib import Path

import numpy as np

import config
from ingestion.loader import Chunk, load_corpus
from retrieval.embeddings import get_backend, tokenize


def index_path(backend_name: str) -> Path:
    # tfidf keeps the original filename: storage/index/index.pkl is the artifact every
    # threat set through RESULTS_2026-08-08.md was generated against.
    if backend_name == "tfidf":
        return config.STORE_DIR / "index.pkl"
    return config.STORE_DIR / f"index_{backend_name}.pkl"


def chunks_path(backend_name: str) -> Path:
    """Human-readable dump of the chunks an index was built over. Written for
    inspection only -- the pickle is authoritative, so the two can never desync."""
    if backend_name == "tfidf":
        return config.STORE_DIR / "chunks.json"
    return config.STORE_DIR / f"chunks_{backend_name}.json"


@dataclass
class Hit:
    chunk: Chunk
    score: float


class Retriever:
    def __init__(self, chunks: list[Chunk], backend, matrix: np.ndarray):
        self.chunks = chunks
        self.backend = backend
        self.matrix = matrix  # (n_chunks, dim); L2-normalized for the vector-space backends

    # ---- build / persist ----
    @classmethod
    def build(cls, backend_name: str | None = None) -> "Retriever":
        chunks = load_corpus()
        backend = get_backend(backend_name)
        texts = [c.text for c in chunks]
        backend.fit(texts)
        matrix = backend.transform(texts)
        r = cls(chunks, backend, matrix)
        r.save()
        return r

    def save(self):
        payload = [c.to_dict() for c in self.chunks]
        with open(index_path(self.backend.name), "wb") as f:
            pickle.dump({"backend": self.backend, "matrix": self.matrix,
                         "backend_name": self.backend.name, "chunks": payload}, f)
        chunks_path(self.backend.name).write_text(json.dumps(payload, indent=2))

    @classmethod
    def load(cls, backend_name: str | None = None) -> "Retriever":
        name = (backend_name or config.EMBEDDING_BACKEND).lower()
        path = index_path(name)
        if not path.exists():
            return cls.build(name)
        with open(path, "rb") as f:
            blob = pickle.load(f)
        backend = blob["backend"]
        matrix = blob["matrix"]
        # Guard against an index built by a different backend being served under this
        # name -- a silent mismatch would run an experiment on the wrong retriever.
        if blob.get("backend_name", backend.name) != backend.name or backend.name != name:
            print(f"[index] {path.name} holds a '{backend.name}' index but '{name}' was "
                  f"requested; rebuilding")
            return cls.build(name)

        raw = blob.get("chunks")
        if raw is None:  # index written before chunks moved into the pickle
            raw = json.loads(chunks_path(name).read_text())
        if len(raw) != matrix.shape[0]:
            # The sidecar was written by a later, larger corpus. Re-labelling this
            # matrix's rows with it would silently return the wrong chunk for every
            # hit, so rebuild against the corpus as it stands instead.
            print(f"[index] {path.name} has {matrix.shape[0]} rows but {len(raw)} chunks "
                  f"were found; rebuilding against the current corpus")
            return cls.build(name)
        return cls([Chunk(**c) for c in raw], backend, matrix)

    # ---- query ----
    def search(self, query: str, k: int | None = None, source: str | None = None,
               hybrid: bool = True, exclude_kinds: list[str] | None = None) -> list[Hit]:
        k = k or config.TOP_K
        qvec = self.backend.transform_query([query])[0]
        sim = self.matrix @ qvec  # cosine for the vector-space backends, BM25 sum for bm25

        scores = sim.copy()
        if hybrid:
            kw = self._keyword_overlap(query)
            # blend; keyword gets a modest weight, enough to surface exact IDs.
            # BM25 scores are an unbounded sum, so scale them into [0, 1] first or the
            # 0.2 keyword term would be rounding error against a raw score of ~15.
            # Scaling by the per-query max is rank-preserving and only ever compares
            # scores within one query. Cosine backends are already in range and are
            # left untouched, so their blend is bit-for-bit what it always was.
            if not getattr(self.backend, "normalized_scores", True):
                peak = float(scores.max()) if scores.size else 0.0
                if peak > 0:
                    scores = scores / peak
            scores = 0.8 * scores + 0.2 * kw

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
        q_terms = {t.lower() for t in tokenize(query)}
        out = np.zeros(len(self.chunks), dtype=np.float32)
        if not q_terms:
            return out
        for i, c in enumerate(self.chunks):
            c_terms = {t.lower() for t in tokenize(c.text + " " + c.section)}
            if not c_terms:
                continue
            out[i] = len(q_terms & c_terms) / len(q_terms)
        return out


if __name__ == "__main__":
    import sys
    r = Retriever.build(sys.argv[1] if len(sys.argv) > 1 else None)
    print(f"Indexed {len(r.chunks)} chunks with backend '{r.backend.name}'")
    print(f"Matrix shape: {r.matrix.shape}")
    print(f"Persisted to {index_path(r.backend.name)}")
