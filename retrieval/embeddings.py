"""Pluggable embedding / retrieval-scoring backends.

Default backend is TF-IDF (scikit-learn) so the pipeline runs with no model
downloads. `bm25` upgrades the lexical scoring; `sbert` upgrades to dense
semantic embeddings when available.

All backends expose:
    fit(texts)
    transform(texts)       -> np.ndarray   (document side)
    transform_query(texts) -> np.ndarray   (query side)
    name, normalized_scores

`transform_query` exists because BM25 is asymmetric: the document side carries
the IDF and length-normalized term weights, the query side is bare term
presence. For the vector-space backends the two sides are identical.

`normalized_scores` tells the retriever whether `matrix @ qvec` already lands in
[0, 1] (cosine, for the vector-space backends) or is an unbounded sum (BM25).
The retriever needs to know before blending in the keyword signal -- see
Retriever.search().
"""
from __future__ import annotations
import re
from collections import Counter

import numpy as np

import config

# Shared tokenizer. Keeps LINDDUN node IDs like "Dd.1.1" / "L.2.2.1" intact as
# single tokens -- sklearn's default token pattern shatters them into "Dd", and
# exact node IDs are the highest-signal terms in this corpus.
_TOKEN_RE = re.compile(r"[A-Za-z]+\.[0-9.]+[0-9]|[A-Za-z0-9]+")


def tokenize(text: str) -> list[str]:
    return _TOKEN_RE.findall(text)


class TfidfBackend:
    name = "tfidf"
    normalized_scores = True  # L2-normalized rows -> dot product is cosine

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

    def transform_query(self, texts: list[str]) -> np.ndarray:
        return self.transform(texts)


class Bm25Backend:
    """Okapi BM25, expressed as a matrix so it drops into the existing retriever.

    BM25's document-side weight does not depend on the query, so the whole score
    factorizes into `doc_weights @ query_presence`:

        score(q, d) = sum_{t in q}  idf(t) * tf(t,d)*(k1+1)
                                    ---------------------------------------
                                    tf(t,d) + k1*(1 - b + b*|d|/avg_dl)

    Two differences from TfidfBackend that are the point of the backend:

    - Term frequency saturates at k1+1 instead of growing as 1+log(tf).
    - Length normalization is explicit and tunable via b (b=0 disables it),
      against the corpus mean length, rather than falling out of L2/cosine
      normalization of the whole vector. This corpus needs it: the LINDDUN
      chunks run 5-266 words (median 24.5, mean 32.5), because two-line
      mapping_row chunks and long tree_node chunks share one index.

    IDF uses the Lucene form, log(1 + (N-df+0.5)/(df+0.5)), rather than the raw
    Robertson-Sparck-Jones numerator. RSJ goes negative once a term appears in
    more than half the corpus, which would make a chunk containing the query
    term rank *below* one that does not. The Lucene form decays smoothly to ~0
    instead, which is the behaviour actually wanted here -- every LINDDUN chunk
    says "data" and "privacy", and those terms should contribute nothing rather
    than actively penalize.

    Unigrams only (TfidfBackend uses 1-2 grams). Standard BM25 is a unigram
    model; counting bigrams toward |d| would distort the length normalization,
    and "BM25" in a write-up should mean the thing reviewers expect.
    """

    name = "bm25"
    normalized_scores = False  # unbounded sum, not cosine

    def __init__(self, k1: float | None = None, b: float | None = None):
        from sklearn.feature_extraction.text import ENGLISH_STOP_WORDS
        self._stop = ENGLISH_STOP_WORDS
        self.k1 = config.BM25_K1 if k1 is None else k1
        self.b = config.BM25_B if b is None else b
        self.vocab: dict[str, int] = {}
        self.idf: np.ndarray | None = None
        self.avg_len = 0.0

    def _terms(self, text: str) -> list[str]:
        return [t for t in (tok.lower() for tok in tokenize(text)) if t not in self._stop]

    def fit(self, texts: list[str]):
        docs = [self._terms(t) for t in texts]
        for d in docs:
            for t in d:
                if t not in self.vocab:
                    self.vocab[t] = len(self.vocab)

        n_docs = len(docs)
        df = np.zeros(len(self.vocab), dtype=np.float32)
        for d in docs:
            for t in set(d):
                df[self.vocab[t]] += 1.0
        self.idf = np.log(1.0 + (n_docs - df + 0.5) / (df + 0.5)).astype(np.float32)

        lengths = [len(d) for d in docs]
        self.avg_len = float(np.mean(lengths)) if lengths else 0.0

    def _require_fit(self):
        if self.idf is None:
            raise RuntimeError("Bm25Backend.fit() must be called before transform()")

    def transform(self, texts: list[str]) -> np.ndarray:
        """Document side: IDF-weighted, length-normalized, saturated term weights."""
        self._require_fit()
        m = np.zeros((len(texts), len(self.vocab)), dtype=np.float32)
        for i, text in enumerate(texts):
            terms = self._terms(text)
            if not terms:
                continue
            # avg_len is 0 only for an empty corpus, which fit() would have made unusable anyway
            len_ratio = len(terms) / self.avg_len if self.avg_len else 1.0
            denom_norm = self.k1 * (1.0 - self.b + self.b * len_ratio)
            for t, tf in Counter(terms).items():
                j = self.vocab.get(t)
                if j is None:  # unseen term (query-time only); no document dimension to fill
                    continue
                m[i, j] = self.idf[j] * (tf * (self.k1 + 1.0)) / (tf + denom_norm)
        return m

    def transform_query(self, texts: list[str]) -> np.ndarray:
        """Query side: bare term presence. Standard Okapi ignores query-side term
        frequency (the k3 variant is for long queries; flow descriptions are short)."""
        self._require_fit()
        m = np.zeros((len(texts), len(self.vocab)), dtype=np.float32)
        for i, text in enumerate(texts):
            for t in set(self._terms(text)):
                j = self.vocab.get(t)
                if j is not None:
                    m[i, j] = 1.0
        return m


class SbertBackend:
    name = "sbert"
    normalized_scores = True

    def __init__(self, model_name: str = "all-MiniLM-L6-v2"):
        from sentence_transformers import SentenceTransformer
        self.model = SentenceTransformer(model_name)

    def fit(self, texts: list[str]):
        pass  # pretrained, no fit needed

    def transform(self, texts: list[str]) -> np.ndarray:
        emb = self.model.encode(texts, normalize_embeddings=True, convert_to_numpy=True)
        return emb.astype(np.float32)

    def transform_query(self, texts: list[str]) -> np.ndarray:
        return self.transform(texts)


def get_backend(name: str | None = None):
    backend = (name or config.EMBEDDING_BACKEND).lower()
    if backend == "bm25":
        return Bm25Backend()
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
