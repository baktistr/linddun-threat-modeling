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
import base64
import json
from abc import ABC, abstractmethod
from dataclasses import dataclass
from pathlib import Path

import config
from generation.schema import THREAT_TOOL_SCHEMA

TOOL_NAME = THREAT_TOOL_SCHEMA["name"]
DEFAULT_MAX_TOKENS = 2000


@dataclass(frozen=True)
class ImageInput:
    """An image to send alongside the prompt, for the DFD-image adapter (adapters/vision.py).

    Carried as base64 rather than a path so backends never touch the filesystem, and so the same
    ImageInput can be replayed against several providers -- the two vendor message shapes differ
    only in how they wrap these same bytes.
    """
    b64: str
    media_type: str = "image/png"

    @staticmethod
    def from_path(path: str | Path) -> "ImageInput":
        p = Path(path)
        suffix = p.suffix.lower()
        media = {".png": "image/png", ".jpg": "image/jpeg", ".jpeg": "image/jpeg",
                 ".gif": "image/gif", ".webp": "image/webp"}.get(suffix)
        if media is None:
            raise ValueError(f"unsupported image type {suffix!r} for {p}")
        return ImageInput(base64.b64encode(p.read_bytes()).decode(), media)


def _openai_content(prompt: str, image: ImageInput | None):
    """OpenAI-compatible message content. A bare string when there's no image, so the text-only
    path over the wire is byte-identical to what it was before images existed."""
    if image is None:
        return prompt
    return [{"type": "text", "text": prompt},
            {"type": "image_url",
             "image_url": {"url": f"data:{image.media_type};base64,{image.b64}"}}]


def _anthropic_content(prompt: str, image: ImageInput | None):
    if image is None:
        return prompt
    return [{"type": "text", "text": prompt},
            {"type": "image", "source": {"type": "base64", "media_type": image.media_type,
                                         "data": image.b64}}]


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

    @property
    def model(self) -> str:
        """The concrete model/deployment behind this backend.

        Separate from `name` (the provider) because that is the axis a multi-model experiment
        varies: "azure" is not an answer to "which model produced this DFD?". Every derived
        artifact records it, so a run stays attributable after the config that produced it moves
        on -- see runs.py.
        """
        raise NotImplementedError

    @abstractmethod
    def call_tool(self, prompt: str, tool_schema: dict,
                  max_tokens: int = DEFAULT_MAX_TOKENS,
                  image: ImageInput | None = None) -> dict:
        """Return the arguments of the model's forced call to `tool_schema`.

        Returns {} if the model produced no parseable call -- callers must treat that as "no
        answer", never as "an empty answer that happens to be valid".

        `image` is the DFD-image adapter's input. It is a parameter here for the same reason
        `max_tokens` is: welding image handling into one backend would mean either duplicating
        three providers' auth, or the adapter reaching for a vendor SDK directly. Every text-only
        caller is unaffected -- with image=None the message content stays a bare string.
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

    @property
    def model(self) -> str:
        return config.CLAUDE_MODEL

    def call_tool(self, prompt: str, tool_schema: dict,
                  max_tokens: int = DEFAULT_MAX_TOKENS,
                  image: ImageInput | None = None) -> dict:
        name = tool_schema["name"]
        resp = self.client.messages.create(
            model=config.CLAUDE_MODEL,
            max_tokens=max_tokens,
            tools=[tool_schema],
            tool_choice={"type": "tool", "name": name},
            messages=[{"role": "user", "content": _anthropic_content(prompt, image)}],
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

    @property
    def model(self) -> str:
        return config.OPENAI_MODEL

    def call_tool(self, prompt: str, tool_schema: dict,
                  max_tokens: int = DEFAULT_MAX_TOKENS,
                  image: ImageInput | None = None) -> dict:
        """Sends the token budget, unlike before.

        This method accepted `max_tokens` and never passed it on, so a 16000-token adapter
        payload silently ran under whatever the endpoint's default was and truncated mid-JSON --
        the exact failure the Azure backend already documents, and one that reads as a model
        failure rather than a budget one. Newer models want `max_completion_tokens` while
        OpenAI-compatible endpoints (Groq, Together, Ollama) still take `max_tokens`, so try the
        modern name and fall back on the 400 that rejects it. A rejected request costs nothing,
        so the retry is free; sending neither was not.
        """
        name = tool_schema["name"]
        kwargs = dict(
            model=config.OPENAI_MODEL,
            tools=[_as_openai_tool(tool_schema)],
            tool_choice={"type": "function", "function": {"name": name}},
            messages=[{"role": "user", "content": _openai_content(prompt, image)}],
        )
        try:
            resp = self.client.chat.completions.create(
                **kwargs, max_completion_tokens=max_tokens)
        except Exception as e:                       # openai.BadRequestError, kept SDK-agnostic
            if "max_completion_tokens" not in str(e) and "max_tokens" not in str(e):
                raise
            resp = self.client.chat.completions.create(**kwargs, max_tokens=max_tokens)
        choice = resp.choices[0]
        for call in choice.message.tool_calls or []:
            if call.function.name == name:
                try:
                    return json.loads(call.function.arguments)
                except json.JSONDecodeError as e:
                    # Same budget-vs-model distinction the Azure backend already makes.
                    if choice.finish_reason == "length":
                        raise RuntimeError(
                            f"tool response for {name!r} was truncated at {max_tokens} tokens "
                            f"(finish_reason=length); the payload did not fit. Raise the budget "
                            f"for this call.") from e
                    raise
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

    @property
    def model(self) -> str:
        return config.AZURE_AI_MODEL

    def call_tool(self, prompt: str, tool_schema: dict,
                  max_tokens: int = DEFAULT_MAX_TOKENS,
                  image: ImageInput | None = None) -> dict:
        name = tool_schema["name"]
        resp = self.client.chat.completions.create(
            model=config.AZURE_AI_MODEL,
            tools=[_as_openai_tool(tool_schema)],
            tool_choice={"type": "function", "function": {"name": name}},
            messages=[{"role": "user", "content": _openai_content(prompt, image)}],
            max_completion_tokens=max_tokens,
        )
        choice = resp.choices[0]
        for call in choice.message.tool_calls or []:
            if call.function.name == name:
                try:
                    return json.loads(call.function.arguments)
                except json.JSONDecodeError as e:
                    # A truncated tool call is cut mid-JSON and fails to parse. Turn that into an
                    # actionable budget error rather than a cryptic decode error four frames up --
                    # exactly the "reads as a model failure rather than a budget one" trap the
                    # max_tokens parameter exists to avoid.
                    if choice.finish_reason == "length":
                        raise RuntimeError(
                            f"tool response for {name!r} was truncated at "
                            f"max_completion_tokens={max_tokens} (finish_reason=length); the "
                            f"payload did not fit. Raise the budget for this call.") from e
                    raise
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
