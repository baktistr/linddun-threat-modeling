"""Central configuration for the LINDDUN RAG knowledge base.

Embedding backend is pluggable via the EMBEDDING_BACKEND env var:
  - "tfidf"  (default): zero-dependency, runs anywhere, good enough for week-1 demo
  - "sbert"          : sentence-transformers local model (better semantic recall)
  - "anthropic"      : (placeholder) Voyage/Anthropic-recommended embeddings

The default is deliberately tfidf so the repo runs with no model downloads.
Switch to sbert once you've validated the pipeline and want better retrieval.
"""
from __future__ import annotations
import os
from pathlib import Path

ROOT = Path(__file__).resolve().parent
KB_DIR = ROOT / "knowledge_base"
STORE_DIR = ROOT / "storage" / "index"
STORE_DIR.mkdir(parents=True, exist_ok=True)

# Knowledge base sub-corpora. Each is tagged so retrieval can filter by source.
CORPORA = {
    "linddun": KB_DIR / "linddun",
    "regulations": KB_DIR / "regulations",
    "scenarios": KB_DIR / "scenarios",
}

# Chunking
CHUNK_SIZE = int(os.environ.get("CHUNK_SIZE", "700"))      # target characters per chunk
CHUNK_OVERLAP = int(os.environ.get("CHUNK_OVERLAP", "100"))

# Retrieval
TOP_K = int(os.environ.get("TOP_K", "5"))

# Embedding backend
EMBEDDING_BACKEND = os.environ.get("EMBEDDING_BACKEND", "tfidf").lower()

# LLM generation layer (cli.py ask, generation/). Not required for retrieval.
# Provider is pluggable so threat generation isn't locked to one vendor -- see generation/llm_backend.py.
LLM_PROVIDER = os.environ.get("LLM_PROVIDER", "anthropic").lower()  # anthropic | openai

# Anthropic (Claude)
ANTHROPIC_API_KEY = os.environ.get("ANTHROPIC_API_KEY", "")
CLAUDE_MODEL = os.environ.get("CLAUDE_MODEL", "claude-sonnet-4-6")

# OpenAI, or any provider exposing an OpenAI-compatible /chat/completions endpoint
# (Groq, Together, Ollama, etc.) via OPENAI_BASE_URL.
OPENAI_API_KEY = os.environ.get("OPENAI_API_KEY", "")
OPENAI_MODEL = os.environ.get("OPENAI_MODEL", "gpt-4o")
OPENAI_BASE_URL = os.environ.get("OPENAI_BASE_URL", "") or None
