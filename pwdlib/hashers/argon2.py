import typing

try:
    import argon2.exceptions
    from argon2 import PasswordHasher
except ImportError as e:
    from ..exceptions import HasherNotAvailable

    raise HasherNotAvailable("argon2") from e

from .base import HasherProtocol, ensure_str


class Argon2Hasher(HasherProtocol):
    def __init__(self) -> None:
        self._hasher = PasswordHasher()  # TODO: handle parameters

    @classmethod
    def identify(cls, hash: typing.Union[str, bytes]) -> bool:
        return ensure_str(hash).startswith("$argon2id$")

    def hash(
        self,
        password: typing.Union[str, bytes],
        *,
        salt: typing.Union[bytes, None] = None,
    ) -> str:
        return self._hasher.hash(password, salt=salt)

    def verify(
        self, hash: typing.Union[str, bytes], password: typing.Union[str, bytes]
    ) -> bool:
        try:
            return self._hasher.verify(hash, password)
        except (
            argon2.exceptions.VerificationError,
            argon2.exceptions.InvalidHashError,
        ):
            return False

    def check_needs_rehash(self, hash: typing.Union[str, bytes]) -> bool:
        return self._hasher.check_needs_rehash(ensure_str(hash))
