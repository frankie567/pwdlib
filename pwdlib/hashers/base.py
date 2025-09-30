from __future__ import annotations

import typing


def ensure_str(v: str | bytes, *, encoding: str = "utf-8") -> str:
    return v.decode(encoding) if isinstance(v, bytes) else v


def ensure_bytes(v: str | bytes, *, encoding: str = "utf-8") -> bytes:
    return v.encode(encoding) if isinstance(v, str) else v


class HasherProtocol(typing.Protocol):
    @classmethod
    def identify(cls, hash: str | bytes) -> bool: ...

    def hash(self, password: str | bytes, *, salt: bytes | None = None) -> str: ...

    def verify(self, password: str | bytes, hash: str | bytes) -> bool: ...

    def check_needs_rehash(self, hash: str | bytes) -> bool: ...


__all__ = ["HasherProtocol", "ensure_str"]
