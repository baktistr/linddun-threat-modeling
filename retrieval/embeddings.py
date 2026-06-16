"""Pluggable embedding backends.

Default backend is TF-IDF (scikit-learn) so the pipeline runs with no model
downloads. `sbert` upgrades to dense semantic embeddings when available.
All backends expose: fit(texts), transform(texts) -> np.ndarray (L2-normalized).
"""
from __future__ import annotations
import numpy as np

import config


class TfidfBackend:
    name = "tfidf"

    def __init__(self):
        from sklearn.feature_extraction.text import TfidfVectorizer
        self.vec = TfidfVectorizer(
            lowercase=True, stop_words="english",
            ngram_range=(1, 2), max_features=20000, sublinear_tf=True,
        )
        self._fitted = False

    def fit(self, texts: list[str]):
        self.vec.fit(texts)
        self._fitted = True

    def transform(self, texts: list[str]) -> np.ndarray:
        m = self.vec.transform(texts).toarray().astype(np.float32)
        norms = np.linalg.norm(m, axis=1, keepdims=True)
        norms[norms == 0] = 1.0
        return m / norms


class SbertBackend:
    name = "sbert"

    def __init__(self, model_name: str = "all-MiniLM-L6-v2"):
        from sentence_transformers import SentenceTransformer
        self.model = SentenceTransformer(model_name)

    def fit(self, texts: list[str]):
        pass  # pretrained, no fit needed

    def transform(self, texts: list[str]) -> np.ndarray:
        emb = self.model.encode(texts, normalize_embeddings=True, convert_to_numpy=True)
        return emb.astype(np.float32)


def get_backend():
    backend = config.EMBEDDING_BACKEND
    if backend == "sbert":
        try:
            return SbertBackend()
        except Exception as e:  # noqa: BLE001
            print(f"[embeddings] sbert unavailable ({e}); falling back to tfidf")
            return TfidfBackend()
    if backend == "anthropic":
        print("[embeddings] anthropic backend not yet wired; using tfidf. "
              "Plug a Voyage/embeddings client here in a later week.")
        return TfidfBackend()
    return TfidfBackend()
