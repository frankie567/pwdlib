import typing


def ensure_str(v: typing.Union[str, bytes], *, encoding: str = "utf-8") -> str:
    return v.decode(encoding) if isinstance(v, bytes) else typing.cast(str, v)


def ensure_bytes(v: typing.Union[str, bytes], *, encoding: str = "utf-8") -> bytes:
    return v.encode(encoding) if isinstance(v, str) else v


class HasherProtocol(typing.Protocol):
    @classmethod
    def identify(cls, hash: typing.Union[str, bytes]) -> bool: ...

    def hash(
        self,
        password: typing.Union[str, bytes],
        *,
        salt: typing.Union[bytes, None] = None,
    ) -> str: ...

    def verify(
        self,
        password: typing.Union[str, bytes],
        hash: typing.Union[str, bytes],
    ) -> bool: ...

    def check_needs_rehash(self, hash: typing.Union[str, bytes]) -> bool: ...


__all__ = ["HasherProtocol", "ensure_str"]
