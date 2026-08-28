"""Central configuration for the LINDDUN RAG knowledge base.

Embedding backend is pluggable via the EMBEDDING_BACKEND env var:
  - "bm25"   (default): Okapi BM25 -- saturating TF, tunable length
                        normalization, and IDF that actually discounts the
                        corpus-wide vocabulary. Zero-dependency (numpy +
                        sklearn's stop-word list).
  - "tfidf"          : the earlier default; TF-IDF cosine over 1-2 grams.
  - "sbert"          : sentence-transformers local model (better semantic recall)
  - "anthropic"      : (placeholder) Voyage/Anthropic-recommended embeddings

BM25 is the default because it is what "retrieval baseline" means to a reader of
this work: the rag arm exists to reproduce retrieval-based prior work as a
controlled ablation, and Okapi BM25 is the standard lexical retriever that claim
is measured against. TF-IDF cosine was the week-1 placeholder chosen for having
no model downloads, and BM25 costs nothing on that axis either.

Consequence, stated rather than left implicit: every threat set generated through
RESULTS_2026-08-08.md used tfidf. Those rag-arm artifacts were produced by a
different retriever than the one this code now serves, and must be regenerated
before their numbers are quoted alongside code at this commit. The grounded and
ungrounded arms never touch the index and are unaffected.

bm25 and tfidf are both lexical, so neither fixes vocabulary mismatch between
scenario prose and LINDDUN's formal wording; sbert is the arm that tests that.
Each backend persists to its own index file, so they can be built once and
switched between by env var without a rebuild.
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
EMBEDDING_BACKEND = os.environ.get("EMBEDDING_BACKEND", "bm25").lower()

# Which chunk kinds the rag arm refuses to retrieve. Default is the long-standing
# ["gold_threat"] -- never let the gold answers leak into the retrieved context.
# Measured 2026-08-26: under that default only 2-8% of retrieved context is tree_node
# chunks; the flow query's DFD type vocabulary ("Process", "ExternalEntity", "DataStore")
# matches the 7 mapping-table chunks almost verbatim and crowds the threat trees out.
# Set RAG_EXCLUDE_KINDS to probe that, e.g. tree-nodes-only:
#   RAG_EXCLUDE_KINDS=gold_threat,mapping_row,mapping_invalid,type_definition,raw_json,untyped
# "untyped" means the chunks with no `kind` (the methodology prose).
def _parse_exclude_kinds(raw: str) -> list:
    kinds = []
    for part in raw.split(","):
        part = part.strip()
        if part:
            kinds.append(None if part == "untyped" else part)
    return kinds


RAG_EXCLUDE_KINDS = _parse_exclude_kinds(os.environ.get("RAG_EXCLUDE_KINDS", "gold_threat"))

# BM25 parameters (EMBEDDING_BACKEND=bm25). Defaults are the standard Okapi values.
# k1 controls how fast term frequency saturates; b controls how hard document length
# is normalized (b=0 disables length normalization entirely, b=1 applies it fully).
BM25_K1 = float(os.environ.get("BM25_K1", "1.5"))
BM25_B = float(os.environ.get("BM25_B", "0.75"))

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
