"""OpenAI Chat Completions compatible and Anthropic Messages providers."""
from dataclasses import dataclass
import os

from .http import RequestError, json_request


class ModelError(RuntimeError):
    pass


@dataclass(frozen=True)
class Reply:
    content: str
    input_tokens: int | None
    output_tokens: int | None
    resolved_model: str | None = None


def _tokens(value):
    return value if type(value) is int and 0 <= value <= 100_000_000 else None


def call(model, system, data, timeout, *, schema=None):
    key = os.environ.get(model.api_key_env) if model.api_key_env else None
    if model.api_key_env and not key:
        raise ModelError(f"Missing environment variable {model.api_key_env}")
    headers = {"Content-Type": "application/json", "Accept": "application/json"}
    payload = {"model": model.model, model.token_parameter: model.max_output_tokens,
               "messages": [{"role": "user", "content": data}]}
    if model.temperature is not None:
        payload["temperature"] = model.temperature
    anthropic = model.provider == "anthropic"
    if anthropic:
        headers["anthropic-version"] = "2023-06-01"
        if key:
            headers["x-api-key"] = key
        payload["system"] = system
        path = "/messages"
    else:
        if key:
            headers["Authorization"] = "Bearer " + key
        payload["messages"].insert(0, {"role": "system", "content": system})
        if model.json_schema:
            if schema is None:
                raise ModelError("A response schema is required for this model")
            payload["response_format"] = {
                "type": "json_schema",
                "json_schema": {"name": "codemurphy", "strict": True, "schema": schema},
            }
        elif model.json_mode:
            payload["response_format"] = {"type": "json_object"}
        path = "/chat/completions"
    try:
        result = json_request(model.base_url + path, method="POST", headers=headers,
                              body=payload, timeout=timeout)
    except RequestError as exc:
        raise ModelError(str(exc)) from None
    try:
        usage = result.get("usage") or {}
        if anthropic:
            content = "\n".join(c["text"] for c in result["content"] if c.get("type") == "text")
            base = _tokens(usage.get("input_tokens"))
            cached = [_tokens(usage.get(k, 0)) for k in ("cache_creation_input_tokens", "cache_read_input_tokens")]
            in_tokens = base + sum(cached) if base is not None and None not in cached else None
            out_tokens = _tokens(usage.get("output_tokens"))
            if result.get("stop_reason") in ("max_tokens", "refusal"):
                content = ""
        else:
            choice = result["choices"][0]
            content = choice["message"].get("content")
            if choice.get("finish_reason") in ("length", "content_filter"):
                content = ""
            in_tokens = _tokens(usage.get("prompt_tokens"))
            out_tokens = _tokens(usage.get("completion_tokens"))
        resolved = result.get("model")
        if not isinstance(resolved, str) or not 0 < len(resolved) <= 180:
            resolved = None
        return Reply(content if isinstance(content, str) else "", in_tokens, out_tokens, resolved)
    except (AttributeError, IndexError, KeyError, TypeError):
        raise ModelError("Unrecognized provider response") from None
