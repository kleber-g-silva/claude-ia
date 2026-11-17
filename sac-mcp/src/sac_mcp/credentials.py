"""Armazenamento de segredos no cofre do sistema operacional.

No Windows o backend do `keyring` é o Windows Credential Manager (DPAPI,
vinculado ao usuário logado). Nada é gravado em arquivo nem no repositório.
"""
from __future__ import annotations

from typing import Protocol

import keyring
from keyring.errors import PasswordDeleteError

SERVICE = "sac-mcp"
CLIENT_ID = "client_id"
CLIENT_SECRET = "client_secret"
REFRESH_TOKEN = "refresh_token"


class SecretStore(Protocol):
    def get(self, key: str) -> str | None: ...
    def set(self, key: str, value: str) -> None: ...
    def delete(self, key: str) -> None: ...


class KeyringStore:
    """Cofre do SO. No Windows: Credential Manager, alvo 'sac-mcp'."""

    def __init__(self, service: str = SERVICE) -> None:
        self.service = service

    def get(self, key: str) -> str | None:
        return keyring.get_password(self.service, key)

    def set(self, key: str, value: str) -> None:
        keyring.set_password(self.service, key, value)

    def delete(self, key: str) -> None:
        try:
            keyring.delete_password(self.service, key)
        except PasswordDeleteError:
            pass

    def backend_name(self) -> str:
        kr = keyring.get_keyring()
        return f"{type(kr).__module__}.{type(kr).__name__}"


class MemoryStore:
    """Usado apenas em testes."""

    def __init__(self, initial: dict[str, str] | None = None) -> None:
        self.data = dict(initial or {})

    def get(self, key: str) -> str | None:
        return self.data.get(key)

    def set(self, key: str, value: str) -> None:
        self.data[key] = value

    def delete(self, key: str) -> None:
        self.data.pop(key, None)
