"""Credentials are resolved by the server process at connect time.

Preferred: integrated auth (Windows / Entra ID), where no secret exists anywhere.
Fallback:  a SQL login whose password lives in the OS keychain (Windows
Credential Manager, macOS Keychain, Secret Service) via ``keyring``.

There is deliberately no environment-variable or config-file source: the
password must never be visible to Claude Code, its environment or the repo.
To add a vault (HashiCorp, Azure Key Vault, CyberArk), implement
CredentialProvider and wire it in connection.connect().
"""

from __future__ import annotations

from typing import Protocol


class CredentialError(RuntimeError):
    pass


class CredentialProvider(Protocol):
    def password(self, username: str) -> str: ...


class KeyringProvider:
    def __init__(self, service: str) -> None:
        self.service = service

    def password(self, username: str) -> str:
        try:
            import keyring
        except ImportError as e:  # pragma: no cover - depends on install extras
            raise CredentialError("auth = 'sql-keyring' needs the 'keyring' package") from e
        pw = keyring.get_password(self.service, username)
        if not pw:
            raise CredentialError(
                f"no password in the OS keychain for service {self.service!r}, user {username!r}. "
                f"Store it with: python -m keyring set {self.service} {username}"
            )
        return pw
