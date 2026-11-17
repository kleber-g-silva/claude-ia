"""Mascaramento de segredos em logs e mensagens de erro."""
from __future__ import annotations

import logging
import re
import sys

_PATTERNS = [
    (re.compile(r"(?i)(bearer\s+)[A-Za-z0-9\-._~+/]+=*"), r"\1***"),
    (re.compile(r"eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]*"), "***JWT***"),
    (re.compile(r"(?i)((?:client_secret|client_id|refresh_token|access_token|id_token|code|code_verifier|password)"
                r"[\"']?\s*[:=]\s*[\"']?)[^\s&\"',}]+"), r"\1***"),
    (re.compile(r"(?i)(basic\s+)[A-Za-z0-9+/]+=*"), r"\1***"),
]


def redact(text: str) -> str:
    for pattern, repl in _PATTERNS:
        text = pattern.sub(repl, text)
    return text


class RedactingFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        record.msg = redact(record.getMessage())
        record.args = None
        return True


def setup_logging(level: int = logging.INFO) -> None:
    """Logs só em stderr (stdout é o canal do protocolo MCP via stdio)."""
    handler = logging.StreamHandler(sys.stderr)
    handler.addFilter(RedactingFilter())
    handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s"))
    root = logging.getLogger()
    root.handlers[:] = [handler]
    root.setLevel(level)
    # httpx/httpcore em DEBUG registrariam headers; mantenha em WARNING.
    for noisy in ("httpx", "httpcore"):
        logging.getLogger(noisy).setLevel(logging.WARNING)
