"""Validated configuration shared by the CLI and the GitHub integration."""
from dataclasses import dataclass
import json
import math
from pathlib import PurePosixPath
import re
from urllib.parse import urlsplit

RUBRIC = {
    "security": "Authentication, tenant isolation, injection, unsafe defaults, sensitive data.",
    "correctness": "Behavior regressions, data integrity, state transitions, compatibility.",
    "scalability": "Unbounded work, N+1 calls, contention, timeouts and backpressure.",
    "clarity": "Specific ambiguity that makes a defect likely or the change hard to maintain.",
    "tests": "A specific changed behavior with a missing or ineffective regression test.",
    "edge-cases": "Empty inputs, limits, races, retries, time zones and failure paths.",
}
SEVERITIES = ("low", "medium", "high", "critical")
REPO = re.compile(r"[A-Za-z0-9][A-Za-z0-9-]{0,99}/[A-Za-z0-9_.-]{1,100}\Z")
SHA = re.compile(r"[a-f0-9]{40}\Z")
LABEL = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}\Z")
ENV = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,79}\Z")


class ConfigError(ValueError):
    pass


def obj(value, fields, label):
    if not isinstance(value, dict):
        raise ConfigError(f"{label} must be an object")
    unknown = value.keys() - set(fields.split())
    if unknown:
        raise ConfigError(f"Unknown {label} keys: {', '.join(sorted(unknown))}")
    return value


def string(value, label, limit=4000):
    if not isinstance(value, str) or not value.strip() or len(value) > limit or "\x00" in value:
        raise ConfigError(f"{label} must be a non-empty string of at most {limit} characters")
    return value


def integer(value, label, low, high):
    if type(value) is not int or not low <= value <= high:
        raise ConfigError(f"{label} must be an integer from {low} to {high}")
    return value


def array(value, label, limit):
    if not isinstance(value, list) or len(value) > limit:
        raise ConfigError(f"{label} must be an array of at most {limit} items")
    return value


def number(value, label, low, high):
    if type(value) not in (int, float) or not low <= value <= high or not math.isfinite(value):
        raise ConfigError(f"{label} must be a finite number from {low} to {high}")
    return value


def repo_name(value):
    return isinstance(value, str) and bool(REPO.fullmatch(value)) and value.split("/")[1] not in (".", "..")


def safe_path(path):
    return (isinstance(path, str) and bool(path) and len(path) <= 1024 and
            not any(ord(c) < 32 or ord(c) == 127 or 0xD800 <= ord(c) <= 0xDFFF for c in path) and
            "\\" not in path and all(p not in ("", ".", "..") for p in path.split("/")))


def sensitive_path(path):
    if not safe_path(path):
        return True
    parts = PurePosixPath(path.lower()).parts
    name = parts[-1]
    return (any(p in {".git", ".ssh", ".aws", ".gnupg"} for p in parts) or
            name in {"id_rsa", "id_ed25519", ".netrc", ".npmrc", ".pypirc", "credentials.json",
                     "secrets.json", "secrets.yaml", "secrets.yml"} or
            name == ".env" or name.startswith(".env.") or
            name.endswith((".pem", ".p12", ".pfx", ".key", ".keystore")))


def match_path(path, pattern):
    """* stays inside a segment; ** can span segments, including zero."""
    pieces = re.split(r"(\*\*/|\*\*|\*|\?)", pattern)
    replacements = {"**/": "(?:.*/)?", "**": ".*", "*": "[^/]*", "?": "[^/]"}
    return bool(re.fullmatch("".join(replacements.get(p, re.escape(p)) for p in pieces), path))


@dataclass(frozen=True)
class Model:
    id: str
    provider: str
    model: str
    base_url: str
    api_key_env: str | None
    input_usd_per_million: float | None
    output_usd_per_million: float | None
    max_output_tokens: int
    token_parameter: str
    json_mode: bool
    json_schema: bool
    temperature: float | None


@dataclass(frozen=True)
class Linked:
    id: str
    commit: str
    files: tuple[str, ...]
    repo: str | None
    local: str | None


@dataclass(frozen=True)
class Config:
    models: tuple[Model, ...] = ()
    primary: str | None = None
    categories: tuple[str, ...] = tuple(RUBRIC)
    exclude: tuple[str, ...] = ()
    language: str = "English"
    instructions: str = ""
    rules: tuple[tuple[tuple[str, ...], str], ...] = ()
    min_severity: str = "medium"
    min_confidence: float = 0.70
    max_comments: int = 12
    structured_comments: bool = False
    verify_with: str | None = None
    chunk_chars: int = 14000
    max_diff_chars: int = 80000
    max_context_chars: int = 8000
    max_batches: int = 12
    max_parallel: int = 4
    timeout: int = 75
    files: tuple[str, ...] = ()
    linked: tuple[Linked, ...] = ()

    def excluded(self, path):
        return sensitive_path(path) or any(match_path(path, pattern) for pattern in self.exclude)

    def instructions_for(self, paths):
        return tuple((patterns, text) for patterns, text in self.rules if
                     any(match_path(path, pattern) for path in paths for pattern in patterns))


def _model(value):
    m = obj(value, "id provider model base_url api_key_env input_usd_per_million "
                   "output_usd_per_million max_output_tokens token_parameter json_mode json_schema temperature", "model")
    identifier = string(m.get("id"), "model.id", 64)
    if not LABEL.fullmatch(identifier) or identifier in {"static", "combined", "published-primary"}:
        raise ConfigError("Invalid or reserved model.id")
    provider = m.get("provider", "openai-compatible")
    if provider not in ("openai-compatible", "anthropic"):
        raise ConfigError("model.provider must be openai-compatible or anthropic")
    anthropic = provider == "anthropic"
    default_url = "https://api.anthropic.com/v1" if anthropic else "https://api.openai.com/v1"
    url = string(m.get("base_url", default_url), "model.base_url", 500).rstrip("/")
    try:
        u = urlsplit(url)
        if (not u.hostname or u.username is not None or u.password is not None or
                u.query or u.fragment or any(ord(c) <= 32 for c in url) or
                not (u.scheme == "https" or
                     u.scheme == "http" and u.hostname in {"localhost", "127.0.0.1", "::1"})):
            raise ValueError
        _ = u.port
    except ValueError:
        raise ConfigError("model.base_url must be HTTPS (HTTP is allowed on loopback only)") from None
    key_env = m.get("api_key_env", "ANTHROPIC_API_KEY" if anthropic else "OPENAI_API_KEY")
    if key_env is not None and (not isinstance(key_env, str) or not ENV.fullmatch(key_env)):
        raise ConfigError("model.api_key_env must be an environment variable name or null")
    if key_env in ("GITHUB_TOKEN", "GH_TOKEN", "CODEMURPHY_GITHUB_TOKEN", "CODEMURPHY_CONTEXT_TOKEN"):
        raise ConfigError("GitHub credential environment variables are reserved for repository access")
    key_hosts = {"OPENAI_API_KEY": "api.openai.com", "ANTHROPIC_API_KEY": "api.anthropic.com",
                 "GEMINI_API_KEY": "generativelanguage.googleapis.com"}
    if key_env in key_hosts and (u.scheme != "https" or u.hostname != key_hosts[key_env] or
                                 u.port not in (None, 443)):
        raise ConfigError("Use a dedicated API key environment variable for a custom provider URL")
    param = m.get("token_parameter", "max_completion_tokens" if url == default_url and not anthropic else "max_tokens")
    if param not in ("max_completion_tokens", "max_tokens") or anthropic and param != "max_tokens":
        raise ConfigError("Unsupported model.token_parameter")
    json_mode, json_schema = m.get("json_mode", False), m.get("json_schema", False)
    if type(json_mode) is not bool or type(json_schema) is not bool or anthropic and (json_mode or json_schema):
        raise ConfigError("model.json_mode and model.json_schema are booleans for OpenAI-compatible endpoints")
    temperature = (number(m["temperature"], "model.temperature", 0, 1 if anthropic else 2)
                   if "temperature" in m else None)
    prices = []
    for name in ("input_usd_per_million", "output_usd_per_million"):
        prices.append(number(m[name], f"model.{name}", 0, 1_000_000) if name in m else None)
    if (prices[0] is None) != (prices[1] is None):
        raise ConfigError("Set both per-million prices or leave both unset")
    return Model(identifier, provider, string(m.get("model"), "model.model", 180), url,
                 key_env, *prices, integer(m.get("max_output_tokens", 2400), "max_output_tokens", 256, 16000), param, json_mode, json_schema, temperature)


def _paths(value):
    paths = array(value, "context files", 24)
    if any(sensitive_path(p) for p in paths):
        raise ConfigError("Context paths must be safe repository-relative files and cannot be credential paths")
    return tuple(dict.fromkeys(paths))


def _linked(value):
    entry = obj(value, "id repo local commit files", "linked context")
    identifier = string(entry.get("id"), "linked.id", 64)
    commit = string(entry.get("commit"), "linked.commit", 40)
    if not LABEL.fullmatch(identifier) or identifier == "project" or not SHA.fullmatch(commit):
        raise ConfigError("Linked context needs a unique id and an immutable 40-character commit SHA")
    repo, local = entry.get("repo"), entry.get("local")
    if (repo is None) == (local is None) or repo is not None and not repo_name(repo):
        raise ConfigError("A linked context needs exactly one of repo (owner/name) or local")
    paths = _paths(entry.get("files", []))
    if not paths:
        raise ConfigError("Linked context needs at least one explicitly listed file")
    return Linked(identifier, commit, paths, repo, string(local, "linked.local", 1024) if local is not None else None)


def load_config(raw=None):
    if raw is None:
        raw = {}
    if isinstance(raw, str):
        try:
            raw = json.loads(raw)
        except ValueError as exc:
            raise ConfigError(f"Invalid config JSON: {exc.msg if isinstance(exc, json.JSONDecodeError) else 'invalid value'}") from None
    obj(raw, "models primary review context", "config")
    review = obj(raw.get("review", {}), "categories exclude language instructions rules min_severity "
                 "min_confidence max_comments chunk_chars max_diff_chars max_context_chars max_batches "
                 "max_parallel timeout structured_comments verify_with", "review")
    context = obj(raw.get("context", {}), "files linked", "context")
    models = tuple(_model(x) for x in array(raw.get("models", []), "models", 8))
    ids = {m.id for m in models}
    primary = raw.get("primary", models[0].id if models else None)
    if len(ids) != len(models) or (models and (not isinstance(primary, str) or primary not in ids)) or (not models and primary is not None):
        raise ConfigError("Use unique model IDs and select a configured primary model")
    structured = review.get("structured_comments", False)
    verifier = review.get("verify_with")
    if type(structured) is not bool:
        raise ConfigError("review.structured_comments must be a boolean")
    if verifier is not None:
        if not isinstance(verifier, str) or verifier not in ids:
            raise ConfigError("review.verify_with must be a configured model ID or null")
        by_id = {m.id: m for m in models}
        if by_id[primary].model.casefold() == by_id[verifier].model.casefold():
            raise ConfigError("review.verify_with must use a different model from the primary")
    categories = tuple(array(review.get("categories", list(RUBRIC)), "categories", len(RUBRIC)))
    if not categories or any(not isinstance(c, str) or c not in RUBRIC for c in categories) or len(set(categories)) != len(categories):
        raise ConfigError("Review categories must be distinct rubric keys")
    severity = review.get("min_severity", "medium")
    if severity not in SEVERITIES:
        raise ConfigError("Invalid min_severity")
    instructions = review.get("instructions", "")
    if instructions != "":
        string(instructions, "review.instructions")
    def patterns(value):
        return tuple(string(x, "path pattern", 200) for x in array(value, "path patterns", 30))
    rules = []
    for rule in array(review.get("rules", []), "rules", 10):
        obj(rule, "paths instructions", "path rule")
        paths = patterns(rule.get("paths"))
        if not paths:
            raise ConfigError("A path rule needs at least one pattern")
        rules.append((paths, string(rule.get("instructions"), "rule.instructions", 1500)))
    linked = tuple(_linked(x) for x in array(context.get("linked", []), "linked repos", 8))
    files = _paths(context.get("files", []))
    if len({x.id for x in linked}) != len(linked) or len(files) + sum(len(x.files) for x in linked) > 48:
        raise ConfigError("Use unique linked IDs and at most 48 total context files")
    def bounded(key, default, low, high):
        return integer(review.get(key, default), key, low, high)
    chunk = bounded("chunk_chars", 14000, 256, 50000)
    budget = bounded("max_diff_chars", 80000, chunk, 500000)
    return Config(models=models, primary=primary, categories=categories,
                  exclude=patterns(review.get("exclude", [])),
                  language=string(review.get("language", "English"), "language", 48),
                  instructions=instructions, rules=tuple(rules), min_severity=severity,
                  min_confidence=number(review.get("min_confidence", .7), "min_confidence", 0, 1),
                  max_comments=bounded("max_comments", 12, 0, 30), structured_comments=structured,
                  verify_with=verifier, chunk_chars=chunk, max_diff_chars=budget,
                  max_context_chars=bounded("max_context_chars", 8000, 0, 30000),
                  max_batches=bounded("max_batches", 12, 1, 32),
                  max_parallel=bounded("max_parallel", 4, 1, 8),
                  timeout=bounded("timeout", 75, 5, 300), files=files, linked=linked)
