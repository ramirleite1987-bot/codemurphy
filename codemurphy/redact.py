"""Best-effort removal of common credential patterns, before any transmission."""
import re

_BEGIN = re.compile(r"-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY-----")
_END = re.compile(r"-----END (?:[A-Z0-9]+ )*PRIVATE KEY-----")
_TOKENS = re.compile(
    r"\b(?:gh[pousr]_[A-Za-z0-9]{32,255}|github_pat_[A-Za-z0-9_]{30,255}"
    r"|(?:AKIA|ASIA)[A-Z0-9]{16}|sk-(?:proj-|ant-api\d+-)?[A-Za-z0-9_-]{24,255}"
    r"|AIza[0-9A-Za-z_-]{35}|xox[baprs]-[0-9A-Za-z-]{16,255}"
    r"|eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{12,})\b"
)
_NAME = (r"(?:[A-Za-z0-9]+[_-])*(?:api[_-]?key|client[_-]?secret|"
         r"access[_-]?token|secret[_-]?(?:access[_-]?)?key|password|"
         r"(?:github|gitlab|slack|oauth|auth)[_-]?token)")
_ASSIGN = re.compile(
    rf"""(?i)(?<![\w-])({_NAME}["']?\s*[:=]\s*(["']))([^"'\s]{{12,}})\2"""
)
_ENV_ASSIGN = re.compile(
    r"^(\s*(?:export\s+)?(?:AWS_SECRET_ACCESS_KEY|OPENAI_API_KEY|ANTHROPIC_API_KEY|"
    r"GEMINI_API_KEY|GITHUB_TOKEN|GH_TOKEN|GITLAB_TOKEN|SLACK_BOT_TOKEN|STRIPE_API_KEY)"
    r"\s*[:=]\s*)([A-Za-z0-9+/_=-]{12,})(?=\s*(?:#.*)?$)"
)
_AUTH = re.compile(r"(?i)(\b(?:https?|postgres(?:ql)?|mysql|redis|mongodb(?:\+srv)?)://[^:/\s@]+:)[^/\s@]+(@)")


class Scrubber:
    def __init__(self):
        self.in_key = False

    def line(self, value):
        begins = bool(_BEGIN.search(value))
        if self.in_key or begins:
            self.in_key = not bool(_END.search(value))
            return "[REDACTED PRIVATE KEY]", begins
        result = _AUTH.sub(r"\1[REDACTED]\2", _TOKENS.sub("[REDACTED]", value))
        result = _ENV_ASSIGN.sub(r"\1[REDACTED]", result)
        result = _ASSIGN.sub(r"\1[REDACTED]\2", result)
        return result, result != value


def redact(text):
    scrubber = Scrubber()
    return "\n".join(scrubber.line(line)[0] for line in text.split("\n"))
