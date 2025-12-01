
"""
llm_client.py

Provider-agnostic client abstraction for τGuardian runtime harness.

This module defines:
  - LLMConfig: normalized configuration for a model call.
  - LLMClient protocol: interface used by τGuardian.
  - Concrete provider clients: OpenAIClient, GeminiClient, FakeClient.
  - Factory helpers: get_client(), generate_code(), generate_code_from_env().
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Optional, Protocol, runtime_checkable, Literal, Tuple
import os

ProviderName = Literal["openai", "gemini", "fake"]


@dataclass(frozen=True)
class LLMConfig:
    """Normalized configuration for a single LLM call."""
    provider: ProviderName
    model: str
    temperature: float = 0.1
    max_tokens: int = 2048
    purpose: str = "code"  # reserved for future use


class LLMError(RuntimeError):
    """Unified error type for all provider failures."""


@runtime_checkable
class LLMClient(Protocol):
    config: LLMConfig

    def generate(self, prompt: str, **kwargs: Any) -> str:
        ...


# ---------------------------------------------------------------------------
# Provider implementations
# ---------------------------------------------------------------------------

class OpenAIClient:
    """OpenAI implementation using openai>=1.0.0."""

    def __init__(self, config: LLMConfig) -> None:
        self.config = config
        try:
            from openai import OpenAI  # type: ignore
        except ImportError as exc:
            raise LLMError(
                "openai package not installed. "
                "Run `pip install openai` in your virtualenv."
            ) from exc

        api_key = os.getenv("OPENAI_API_KEY")
        if not api_key:
            raise LLMError("OPENAI_API_KEY is not set in environment.")
        self._client = OpenAI(api_key=api_key)

    def generate(self, prompt: str, **_: Any) -> str:
        resp = self._client.chat.completions.create(
            model=self.config.model,
            messages=[
                {
                    "role": "system",
                    "content": (
                        "You are an expert software engineer. "
                        "Return ONLY the final code, inside a single fenced code block. "
                        "No explanations, no comments outside code."
                    ),
                },
                {"role": "user", "content": prompt},
            ],
            temperature=self.config.temperature,
            max_tokens=self.config.max_tokens,
        )
        text = resp.choices[0].message.content or ""
        return text


class GeminiClient:
    """Gemini implementation using google-generativeai."""

    def __init__(self, config: LLMConfig) -> None:
        self.config = config
        try:
            import google.generativeai as genai  # type: ignore
        except ImportError as exc:
            raise LLMError(
                "google-generativeai package not installed. "
                "Run `pip install google-generativeai` in your virtualenv."
            ) from exc

        api_key = os.getenv("GEMINI_API_KEY") or os.getenv("GOOGLE_API_KEY")
        if not api_key:
            raise LLMError(
                "GEMINI_API_KEY or GOOGLE_API_KEY must be set in environment "
                "for Gemini provider."
            )

        genai.configure(api_key=api_key)
        self._genai = genai

    def generate(self, prompt: str, **_: Any) -> str:
        model = self._genai.GenerativeModel(self.config.model)
        response = model.generate_content(
            prompt,
            generation_config={
                "temperature": self.config.temperature,
                "max_output_tokens": self.config.max_tokens,
            },
        )

        # Guard against safety blocks / no Part cases where response.text raises
        # a ValueError. We try response.text first, then aggregate candidate parts.
        text = None
        try:
            text = response.text  # type: ignore[attr-defined]
        except Exception:
            text = None

        if text:
            return text

        parts = []
        for cand in getattr(response, "candidates", []) or []:
            content = getattr(cand, "content", None)
            if not content:
                continue
            for part in getattr(content, "parts", []) or []:
                t = getattr(part, "text", None)
                if t:
                    parts.append(t)

        if parts:
            return "\n".join(parts)

        # Last resort: empty string so the harness treats it as a failed
        # generation instead of crashing.
        return ""


class FakeClient:
    """Deterministic stub used for CI and offline testing."""

    def __init__(self, config: LLMConfig) -> None:
        self.config = config

    def generate(self, prompt: str, **_: Any) -> str:
        header = "# TG_FAKE_MODEL is enabled. No real LLM call was made.\n"
        return header + "# Prompt length: " + str(len(prompt)) + "\n"


# ---------------------------------------------------------------------------
# Factory & helpers
# ---------------------------------------------------------------------------

_CLIENT_CACHE: Dict[Tuple[ProviderName, str], LLMClient] = {}


def _make_client(config: LLMConfig) -> LLMClient:
    if os.getenv("TG_FAKE_MODEL", "0") == "1" or config.provider == "fake":
        return FakeClient(config)
    if config.provider == "openai":
        return OpenAIClient(config)
    if config.provider == "gemini":
        return GeminiClient(config)
    raise LLMError(f"Unsupported provider: {config.provider}")


def get_client(config: LLMConfig) -> LLMClient:
    key = (config.provider, config.model)
    if key not in _CLIENT_CACHE:
        _CLIENT_CACHE[key] = _make_client(config)
    return _CLIENT_CACHE[key]


def config_from_env(model_name: Optional[str] = None) -> LLMConfig:
    provider_str = os.getenv("LLM_PROVIDER", "openai").lower()
    if provider_str == "gemini":
        provider: ProviderName = "gemini"
    elif provider_str == "fake":
        provider = "fake"
    else:
        provider = "openai"

    model = model_name or os.getenv("LLM_MODEL_NAME", "")
    if not model:
        raise LLMError(
            "LLM_MODEL_NAME is not set and no model_name was passed to config_from_env()."
        )

    temp = float(os.getenv("LLM_TEMPERATURE", "0.1"))
    max_toks = int(os.getenv("LLM_MAX_TOKENS", "2048"))

    return LLMConfig(
        provider=provider,
        model=model,
        temperature=temp,
        max_tokens=max_toks,
    )


def generate_code(prompt: str, cfg: LLMConfig) -> str:
    client = get_client(cfg)
    return client.generate(prompt)


def generate_code_from_env(prompt: str, model_name: Optional[str] = None) -> str:
    cfg = config_from_env(model_name=model_name)
    return generate_code(prompt, cfg)
