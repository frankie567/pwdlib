import typing


def ensure_str_hash(hash: typing.Union[str, bytes]) -> str:
    return hash.decode("ascii") if isinstance(hash, bytes) else typing.cast(str, hash)


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


__all__ = ["HasherProtocol", "ensure_str_hash"]
