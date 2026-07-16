"""Pluggable LLM backend, mirroring retrieval/embeddings.py's pattern.

The pipeline needs one capability from a model: given a prompt and a tool schema, return the
arguments of a forced call to that tool. Each backend implements that against its provider's API
shape; no caller talks to a vendor SDK directly, so swapping providers is a config change
(LLM_PROVIDER env var), not a code change.

`call_tool` is the primitive; `generate_threats` is the original threat-elicitation caller kept
as a thin wrapper so generation/generate.py is untouched. The generalisation exists because the
source-code -> DFD adapter (adapters/synthesize.py) needs the same forced-tool-call capability
against a *different* schema. Welding the backend to THREAT_TOOL_SCHEMA would have meant either a
second copy of three providers' auth handling, or the adapter reaching for a vendor SDK directly
-- both worse than one parameter.

`max_tokens` is a parameter for the same reason: a whole-DFD payload (14+ elements, 27+ flows,
provenance, rationales) does not fit the 2000 that suffices for one flow's threats, and Azure
truncates mid-JSON with no error when it doesn't fit -- the tool call simply fails to parse, which
looks like a model failure rather than a budget one.
"""
from __future__ import annotations
import json
from abc import ABC, abstractmethod

import config
from generation.schema import THREAT_TOOL_SCHEMA

TOOL_NAME = THREAT_TOOL_SCHEMA["name"]
DEFAULT_MAX_TOKENS = 2000


def _as_openai_tool(schema: dict) -> dict:
    """Anthropic's tool shape -> OpenAI's function shape. Shared by both OpenAI-compatible
    backends so they cannot drift apart."""
    return {
        "type": "function",
        "function": {
            "name": schema["name"],
            "description": schema.get("description", ""),
            "parameters": schema["input_schema"],
        },
    }


class LLMBackend(ABC):
    name: str

    @abstractmethod
    def call_tool(self, prompt: str, tool_schema: dict,
                  max_tokens: int = DEFAULT_MAX_TOKENS) -> dict:
        """Return the arguments of the model's forced call to `tool_schema`.

        Returns {} if the model produced no parseable call -- callers must treat that as "no
        answer", never as "an empty answer that happens to be valid".
        """

    def generate_threats(self, prompt: str) -> dict:
        """Original threat-elicitation entrypoint. Unchanged public API and unchanged behaviour:
        same schema, same forced tool choice, same 2000-token budget."""
        result = self.call_tool(prompt, THREAT_TOOL_SCHEMA, max_tokens=DEFAULT_MAX_TOKENS)
        return result if result else {"threats": []}


class AnthropicBackend(LLMBackend):
    name = "anthropic"

    def __init__(self):
        if not config.ANTHROPIC_API_KEY:
            raise RuntimeError("ANTHROPIC_API_KEY not set (see .env.example).")
        import anthropic
        self.client = anthropic.Anthropic(api_key=config.ANTHROPIC_API_KEY)

    def call_tool(self, prompt: str, tool_schema: dict,
                  max_tokens: int = DEFAULT_MAX_TOKENS) -> dict:
        name = tool_schema["name"]
        resp = self.client.messages.create(
            model=config.CLAUDE_MODEL,
            max_tokens=max_tokens,
            tools=[tool_schema],
            tool_choice={"type": "tool", "name": name},
            messages=[{"role": "user", "content": prompt}],
        )
        for block in resp.content:
            if block.type == "tool_use" and block.name == name:
                return block.input
        return {}


class OpenAIBackend(LLMBackend):
    """OpenAI, or any OpenAI-compatible /chat/completions provider (Groq, Together, Ollama, ...)
    reachable by setting OPENAI_BASE_URL."""
    name = "openai"

    def __init__(self):
        if not config.OPENAI_API_KEY:
            raise RuntimeError("OPENAI_API_KEY not set (see .env.example).")
        import openai
        kwargs = {"api_key": config.OPENAI_API_KEY}
        if config.OPENAI_BASE_URL:
            kwargs["base_url"] = config.OPENAI_BASE_URL
        self.client = openai.OpenAI(**kwargs)

    def call_tool(self, prompt: str, tool_schema: dict,
                  max_tokens: int = DEFAULT_MAX_TOKENS) -> dict:
        name = tool_schema["name"]
        resp = self.client.chat.completions.create(
            model=config.OPENAI_MODEL,
            tools=[_as_openai_tool(tool_schema)],
            tool_choice={"type": "function", "function": {"name": name}},
            messages=[{"role": "user", "content": prompt}],
        )
        for call in resp.choices[0].message.tool_calls or []:
            if call.function.name == name:
                return json.loads(call.function.arguments)
        return {}


class AzureFoundryBackend(LLMBackend):
    """Azure AI Foundry, via the Azure-OpenAI-compatible /chat/completions route on an AIServices
    resource. AZURE_AI_MODEL is a deployment name, not a public model name. Newer deployments
    (e.g. this project's "gpt-5.4") reject `max_tokens`, requiring `max_completion_tokens`
    instead -- the one real difference from OpenAIBackend beyond auth/endpoint shape."""
    name = "azure"

    def __init__(self):
        if not config.AZURE_AI_API_KEY:
            raise RuntimeError("AZURE_AI_API_KEY not set (see .env.example).")
        if not config.AZURE_AI_ENDPOINT:
            raise RuntimeError("AZURE_AI_ENDPOINT not set (see .env.example).")
        import openai
        # Accept either a bare resource root or a full Foundry project endpoint
        # (".../api/projects/<project>") -- the chat-completions route lives at the resource root.
        endpoint = config.AZURE_AI_ENDPOINT.split("/api/projects/")[0]
        self.client = openai.AzureOpenAI(
            azure_endpoint=endpoint,
            api_key=config.AZURE_AI_API_KEY,
            api_version=config.AZURE_AI_API_VERSION,
        )

    def call_tool(self, prompt: str, tool_schema: dict,
                  max_tokens: int = DEFAULT_MAX_TOKENS) -> dict:
        name = tool_schema["name"]
        resp = self.client.chat.completions.create(
            model=config.AZURE_AI_MODEL,
            tools=[_as_openai_tool(tool_schema)],
            tool_choice={"type": "function", "function": {"name": name}},
            messages=[{"role": "user", "content": prompt}],
            max_completion_tokens=max_tokens,
        )
        for call in resp.choices[0].message.tool_calls or []:
            if call.function.name == name:
                return json.loads(call.function.arguments)
        return {}


_BACKENDS: dict[str, type[LLMBackend]] = {
    "anthropic": AnthropicBackend,
    "openai": OpenAIBackend,
    "azure": AzureFoundryBackend,
}


def get_llm_backend(provider: str | None = None) -> LLMBackend:
    name = (provider or config.LLM_PROVIDER).lower()
    cls = _BACKENDS.get(name)
    if cls is None:
        raise ValueError(f"Unknown LLM_PROVIDER '{name}'. Choose from {sorted(_BACKENDS)}.")
    return cls()
