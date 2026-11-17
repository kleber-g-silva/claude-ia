"""Armazenamento de segredos no cofre do sistema operacional.

No Windows o backend do `keyring` é o Windows Credential Manager (DPAPI,
vinculado ao usuário logado). Nada é gravado em arquivo nem no repositório.

Isolamento por conexão: cada conexão usa o serviço "sac-mcp:<conexão>", então
Client ID/Secret e refresh token de um tenant nunca são lidos por outro.
No Credential Manager aparecem como "<chave>@sac-mcp:<conexão>".
"""
from __future__ import annotations

from typing import Protocol

import keyring
from keyring.errors import PasswordDeleteError

SERVICE = "sac-mcp"
CLIENT_ID = "client_id"
CLIENT_SECRET = "client_secret"
REFRESH_TOKEN = "refresh_token"
ALL_KEYS = (CLIENT_ID, CLIENT_SECRET, REFRESH_TOKEN)


def service_for(connection_id: str) -> str:
    from sac_mcp.config import validate_connection_id

    return f"{SERVICE}:{validate_connection_id(connection_id)}"


class SecretStore(Protocol):
    def get(self, key: str) -> str | None: ...
    def set(self, key: str, value: str) -> None: ...
    def delete(self, key: str) -> None: ...
    def has_credentials(self) -> bool: ...
    def delete_all(self) -> None: ...


class KeyringStore:
    """Cofre do SO. No Windows: Credential Manager, alvo 'sac-mcp:<conexão>'."""

    def __init__(self, service: str) -> None:
        self.service = service

    @classmethod
    def for_connection(cls, connection_id: str) -> "KeyringStore":
        return cls(service_for(connection_id))

    def get(self, key: str) -> str | None:
        return keyring.get_password(self.service, key)

    def set(self, key: str, value: str) -> None:
        keyring.set_password(self.service, key, value)

    def delete(self, key: str) -> None:
        try:
            keyring.delete_password(self.service, key)
        except PasswordDeleteError:
            pass

    def has_credentials(self) -> bool:
        return bool(self.get(CLIENT_ID) and self.get(CLIENT_SECRET))

    def delete_all(self) -> None:
        for k in ALL_KEYS:
            self.delete(k)

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

    def has_credentials(self) -> bool:
        return bool(self.get(CLIENT_ID) and self.get(CLIENT_SECRET))

    def delete_all(self) -> None:
        for k in ALL_KEYS:
            self.delete(k)
