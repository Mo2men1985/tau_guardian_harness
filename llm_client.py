from __future__ import annotations

import hashlib
import json
import os
import time
import urllib.request
from dataclasses import dataclass
from typing import Any, Dict, Literal, Optional, Protocol, Tuple, runtime_checkable

ProviderName = Literal["openai", "gemini", "fake", "local_gemma", "ollama"]


class LLMError(RuntimeError):
    pass


@dataclass(frozen=True)
class LLMConfig:
    provider: ProviderName
    model: str
    temperature: float = 0.0
    max_tokens: int = 2048
    seed: Optional[int] = None


@dataclass
class ModelCallEvidence:
    provider: str
    model: str
    temperature: float
    max_tokens: int
    seed: Optional[int]
    started_at_epoch_ms: int
    duration_ms: int
    prompt_sha256: str
    response_sha256: str
    request_id: Optional[str]
    input_tokens: Optional[int]
    output_tokens: Optional[int]
    text: str


@runtime_checkable
class LLMClient(Protocol):
    config: LLMConfig
    def generate(self, prompt: str) -> Tuple[str, Dict[str, Any]]: ...


def _sha(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


class OpenAIClient:
    def __init__(self, config: LLMConfig) -> None:
        self.config = config
        try:
            from openai import OpenAI
        except ImportError as exc:
            raise LLMError("openai package is not installed") from exc
        api_key = os.getenv("OPENAI_API_KEY")
        if not api_key:
            raise LLMError("OPENAI_API_KEY is not set")
        self.client = OpenAI(api_key=api_key)

    def generate(self, prompt: str) -> Tuple[str, Dict[str, Any]]:
        kwargs: Dict[str, Any] = {
            "model": self.config.model,
            "messages": [
                {"role": "system", "content": "Return only the final code. Do not include prose."},
                {"role": "user", "content": prompt},
            ],
            "temperature": self.config.temperature,
            "max_tokens": self.config.max_tokens,
        }
        if self.config.seed is not None:
            kwargs["seed"] = self.config.seed
        try:
            resp = self.client.chat.completions.create(**kwargs)
        except Exception as exc:
            raise LLMError(f"OpenAI request failed: {exc}") from exc
        text = resp.choices[0].message.content or ""
        usage = getattr(resp, "usage", None)
        return text, {
            "request_id": getattr(resp, "id", None),
            "input_tokens": getattr(usage, "prompt_tokens", None) if usage else None,
            "output_tokens": getattr(usage, "completion_tokens", None) if usage else None,
        }


class GeminiClient:
    def __init__(self, config: LLMConfig) -> None:
        self.config = config
        try:
            from google import genai
        except ImportError as exc:
            raise LLMError("google-genai package is not installed") from exc
        api_key = os.getenv("GEMINI_API_KEY") or os.getenv("GOOGLE_API_KEY")
        if not api_key:
            raise LLMError("GEMINI_API_KEY or GOOGLE_API_KEY is not set")
        self.client = genai.Client(api_key=api_key)

    def generate(self, prompt: str) -> Tuple[str, Dict[str, Any]]:
        try:
            response = self.client.models.generate_content(
                model=self.config.model,
                contents=prompt,
                config={
                    "temperature": self.config.temperature,
                    "max_output_tokens": self.config.max_tokens,
                },
            )
        except Exception as exc:
            raise LLMError(f"Gemini request failed: {exc}") from exc
        text = getattr(response, "text", None)
        if not text:
            raise LLMError("Gemini returned no text")
        usage = getattr(response, "usage_metadata", None)
        return text, {
            "request_id": getattr(response, "response_id", None),
            "input_tokens": getattr(usage, "prompt_token_count", None) if usage else None,
            "output_tokens": getattr(usage, "candidates_token_count", None) if usage else None,
        }


class OllamaClient:
    def __init__(self, config: LLMConfig) -> None:
        self.config = config
        self.base_url = os.getenv("OLLAMA_BASE_URL", "http://127.0.0.1:11434").rstrip("/")

    def generate(self, prompt: str) -> Tuple[str, Dict[str, Any]]:
        body = json.dumps({
            "model": self.config.model,
            "prompt": prompt,
            "stream": False,
            "options": {
                "temperature": self.config.temperature,
                "num_predict": self.config.max_tokens,
            },
        }).encode("utf-8")
        request = urllib.request.Request(
            self.base_url + "/api/generate",
            data=body,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=300) as response:
                payload = json.loads(response.read().decode("utf-8"))
        except Exception as exc:
            raise LLMError(f"Ollama request failed: {exc}") from exc
        text = str(payload.get("response") or "")
        if not text:
            raise LLMError("Ollama returned no response text")
        return text, {
            "request_id": None,
            "input_tokens": payload.get("prompt_eval_count"),
            "output_tokens": payload.get("eval_count"),
        }


class FakeClient:
    def __init__(self, config: LLMConfig) -> None:
        self.config = config
    def generate(self, prompt: str) -> Tuple[str, Dict[str, Any]]:
        return "# fake model output\n", {"request_id": "fake", "input_tokens": None, "output_tokens": None}


_CLIENTS: Dict[Tuple[str, str, float, int, Optional[int]], LLMClient] = {}


def config_from_env(model_name: Optional[str] = None) -> LLMConfig:
    provider_raw = os.getenv("LLM_PROVIDER", "openai").lower()
    provider: ProviderName
    if provider_raw in {"openai", "gemini", "fake", "local_gemma", "ollama"}:
        provider = provider_raw  # type: ignore[assignment]
    else:
        raise LLMError(f"unsupported LLM_PROVIDER: {provider_raw}")
    model = model_name or os.getenv("LLM_MODEL_NAME")
    if not model:
        raise LLMError("LLM_MODEL_NAME is not set")
    seed_raw = os.getenv("LLM_SEED")
    seed = int(seed_raw) if seed_raw not in {None, ""} else None
    return LLMConfig(
        provider=provider,
        model=model,
        temperature=float(os.getenv("LLM_TEMPERATURE", "0.0")),
        max_tokens=int(os.getenv("LLM_MAX_TOKENS", "2048")),
        seed=seed,
    )


def _make_client(cfg: LLMConfig) -> LLMClient:
    if cfg.provider == "openai": return OpenAIClient(cfg)
    if cfg.provider == "gemini": return GeminiClient(cfg)
    if cfg.provider == "ollama": return OllamaClient(cfg)
    if cfg.provider == "fake": return FakeClient(cfg)
    if cfg.provider == "local_gemma":
        raise LLMError("local_gemma is retired; use Ollama for local model execution")
    raise LLMError(f"unsupported provider: {cfg.provider}")


def get_client(cfg: LLMConfig) -> LLMClient:
    key = (cfg.provider, cfg.model, cfg.temperature, cfg.max_tokens, cfg.seed)
    if key not in _CLIENTS:
        _CLIENTS[key] = _make_client(cfg)
    return _CLIENTS[key]


def generate_code_with_evidence(prompt: str, cfg: LLMConfig) -> ModelCallEvidence:
    started_at = int(time.time() * 1000)
    monotonic = time.monotonic()
    text, meta = get_client(cfg).generate(prompt)
    duration_ms = int((time.monotonic() - monotonic) * 1000)
    return ModelCallEvidence(
        provider=cfg.provider,
        model=cfg.model,
        temperature=cfg.temperature,
        max_tokens=cfg.max_tokens,
        seed=cfg.seed,
        started_at_epoch_ms=started_at,
        duration_ms=duration_ms,
        prompt_sha256=_sha(prompt),
        response_sha256=_sha(text),
        request_id=meta.get("request_id"),
        input_tokens=meta.get("input_tokens"),
        output_tokens=meta.get("output_tokens"),
        text=text,
    )


def generate_code_with_evidence_from_env(prompt: str, model_name: Optional[str] = None) -> ModelCallEvidence:
    return generate_code_with_evidence(prompt, config_from_env(model_name))


def generate_code_from_env(prompt: str, model_name: Optional[str] = None) -> str:
    return generate_code_with_evidence_from_env(prompt, model_name).text
