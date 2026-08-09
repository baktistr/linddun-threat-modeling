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


def _load_dotenv(path: Path) -> None:
    """Minimal .env loader: KEY=value lines, '#' comments, blank lines skipped. Real shell/CI
    env vars always win -- this only fills in what isn't already set."""
    if not path.exists():
        return
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        if key and key not in os.environ:
            os.environ[key] = value.strip()


_load_dotenv(ROOT / ".env")
KB_DIR = ROOT / "knowledge_base"
STORE_DIR = ROOT / "storage" / "index"
STORE_DIR.mkdir(parents=True, exist_ok=True)

# Knowledge base sub-corpora. Each is tagged so retrieval can filter by source.
CORPORA = {
    "linddun": KB_DIR / "linddun",
    "scenarios": KB_DIR / "scenarios",
    "panoptic": KB_DIR / "panoptic",
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
LLM_PROVIDER = os.environ.get("LLM_PROVIDER", "anthropic").lower()  # anthropic | openai | azure

# Anthropic (Claude)
ANTHROPIC_API_KEY = os.environ.get("ANTHROPIC_API_KEY", "")
CLAUDE_MODEL = os.environ.get("CLAUDE_MODEL", "claude-sonnet-4-6")

# OpenAI, or any provider exposing an OpenAI-compatible /chat/completions endpoint
# (Groq, Together, Ollama, etc.) via OPENAI_BASE_URL.
OPENAI_API_KEY = os.environ.get("OPENAI_API_KEY", "")
OPENAI_MODEL = os.environ.get("OPENAI_MODEL", "gpt-4o")
OPENAI_BASE_URL = os.environ.get("OPENAI_BASE_URL", "") or None

# Azure AI Foundry (Azure OpenAI-compatible route on an AIServices resource). AZURE_AI_ENDPOINT
# is the resource root (e.g. "https://<resource>.services.ai.azure.com/") -- if a full Foundry
# project endpoint ("https://<resource>.services.ai.azure.com/api/projects/<project>") is set
# instead, AzureFoundryBackend strips the "/api/projects/..." suffix automatically.
# AZURE_AI_MODEL is the deployment name (not necessarily the underlying model family's public
# name). Newer deployments (this project's "gpt-5.4") reject `max_tokens` in favor of
# `max_completion_tokens`; AzureFoundryBackend always uses the latter.
AZURE_AI_ENDPOINT = os.environ.get("AZURE_AI_ENDPOINT", "")
AZURE_AI_API_KEY = os.environ.get("AZURE_AI_API_KEY", "")
AZURE_AI_MODEL = os.environ.get("AZURE_AI_MODEL", "gpt-4o")
AZURE_AI_API_VERSION = os.environ.get("AZURE_AI_API_VERSION", "2024-12-01-preview")


# Sampling temperature for every generation call. Pinned at 0 because nothing used to set it, so
# every run went out at the provider default of 1.0 -- full sampling -- and the resulting spread
# (recall ~0.10, citation validity 0.02-0.04 between repeats of one condition) was noise the
# experiment was paying for by default rather than a property of the task. An evaluation that
# reports point estimates has to pin the sampler first and repeat second.
#
# Set GENERATION_TEMPERATURE=none to send nothing and take the deployment's default -- the setting
# to use when the QUESTION is about sampling diversity (e.g. whether unioning several runs elicits
# more threats than one greedy pass), which is a different experiment, not this one's baseline.
_temp_raw = os.environ.get("GENERATION_TEMPERATURE", "0")
GENERATION_TEMPERATURE: float | None = (
    None if _temp_raw.strip().lower() in ("", "none", "default") else float(_temp_raw))


def code_state() -> str:
    """The commit the running code came from, with '-dirty' when tracked files carry
    uncommitted changes.

    Stamped into every sweep artifact's _meta. RESULTS_2026-08-07.md is why: the model sweep's
    source-arm runs were produced by a working tree whose adapter threading was only committed
    afterwards (the recording commit's own code would have raised a TypeError), and the 36-flow
    outlier that resulted could not be traced to any tree. 'unknown' is recorded when git or the
    checkout is unavailable, rather than guessed.
    """
    import subprocess
    try:
        out = subprocess.run(["git", "describe", "--always", "--dirty"], cwd=ROOT,
                             capture_output=True, text=True, timeout=5, check=True)
        return out.stdout.strip() or "unknown"
    except Exception:
        return "unknown"
