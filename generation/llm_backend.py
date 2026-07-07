"""Pluggable LLM backend for threat generation, mirroring retrieval/embeddings.py's pattern.

The generation pipeline needs one capability from a model: given a prompt, return the
`{"threats": [...]}` payload for THREAT_TOOL_SCHEMA via a forced tool/function call. Each backend
implements that against its provider's API shape; generation/generate.py never talks to a vendor
SDK directly, so swapping providers is a config change (LLM_PROVIDER env var), not a code change.
"""
from __future__ import annotations
import json
from abc import ABC, abstractmethod

import config
from generation.schema import THREAT_TOOL_SCHEMA

TOOL_NAME = THREAT_TOOL_SCHEMA["name"]


class LLMBackend(ABC):
    name: str

    @abstractmethod
    def generate_threats(self, prompt: str) -> dict:
        """Return {"threats": [...]} parsed from the model's forced tool call."""


class AnthropicBackend(LLMBackend):
    name = "anthropic"

    def __init__(self):
        if not config.ANTHROPIC_API_KEY:
            raise RuntimeError("ANTHROPIC_API_KEY not set (see .env.example).")
        import anthropic
        self.client = anthropic.Anthropic(api_key=config.ANTHROPIC_API_KEY)

    def generate_threats(self, prompt: str) -> dict:
        resp = self.client.messages.create(
            model=config.CLAUDE_MODEL,
            max_tokens=2000,
            tools=[THREAT_TOOL_SCHEMA],
            tool_choice={"type": "tool", "name": TOOL_NAME},
            messages=[{"role": "user", "content": prompt}],
        )
        for block in resp.content:
            if block.type == "tool_use" and block.name == TOOL_NAME:
                return block.input
        return {"threats": []}


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

    def generate_threats(self, prompt: str) -> dict:
        tool = {
            "type": "function",
            "function": {
                "name": TOOL_NAME,
                "description": THREAT_TOOL_SCHEMA["description"],
                "parameters": THREAT_TOOL_SCHEMA["input_schema"],
            },
        }
        resp = self.client.chat.completions.create(
            model=config.OPENAI_MODEL,
            tools=[tool],
            tool_choice={"type": "function", "function": {"name": TOOL_NAME}},
            messages=[{"role": "user", "content": prompt}],
        )
        tool_calls = resp.choices[0].message.tool_calls or []
        for call in tool_calls:
            if call.function.name == TOOL_NAME:
                return json.loads(call.function.arguments)
        return {"threats": []}


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

    def generate_threats(self, prompt: str) -> dict:
        tool = {
            "type": "function",
            "function": {
                "name": TOOL_NAME,
                "description": THREAT_TOOL_SCHEMA["description"],
                "parameters": THREAT_TOOL_SCHEMA["input_schema"],
            },
        }
        resp = self.client.chat.completions.create(
            model=config.AZURE_AI_MODEL,
            tools=[tool],
            tool_choice={"type": "function", "function": {"name": TOOL_NAME}},
            messages=[{"role": "user", "content": prompt}],
            max_completion_tokens=2000,
        )
        tool_calls = resp.choices[0].message.tool_calls or []
        for call in tool_calls:
            if call.function.name == TOOL_NAME:
                return json.loads(call.function.arguments)
        return {"threats": []}


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
