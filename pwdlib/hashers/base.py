import typing


def ensure_str(v: typing.Union[str, bytes]) -> str:
    return v.decode("utf-8") if isinstance(v, bytes) else typing.cast(str, v)


def ensure_bytes(v: typing.Union[str, bytes]) -> bytes:
    return v.encode("utf-8") if isinstance(v, str) else v


class HasherProtocol(typing.Protocol):
    @classmethod
    def identify(cls, hash: typing.Union[str, bytes]) -> bool:
        ...

    def hash(
        self,
        password: typing.Union[str, bytes],
        *,
        salt: typing.Union[bytes, None] = None,
    ) -> str:
        ...

    def verify(
        self, hash: typing.Union[str, bytes], password: typing.Union[str, bytes]
    ) -> bool:
        ...

    def check_needs_rehash(self, hash: typing.Union[str, bytes]) -> bool:
        ...


__all__ = ["HasherProtocol", "ensure_str"]
