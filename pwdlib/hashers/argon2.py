import typing

try:
    import argon2.exceptions
    from argon2 import PasswordHasher
except ImportError as e:
    from ..exceptions import HasherNotAvailable

    raise HasherNotAvailable("argon2") from e

from .base import HasherProtocol, ensure_str


class Argon2Hasher(HasherProtocol):
    def __init__(
        self,
        time_cost: int = argon2.DEFAULT_TIME_COST,
        memory_cost: int = argon2.DEFAULT_MEMORY_COST,
        parallelism: int = argon2.DEFAULT_PARALLELISM,
        hash_len: int = argon2.DEFAULT_HASH_LENGTH,
        salt_len: int = argon2.DEFAULT_RANDOM_SALT_LENGTH,
        type: argon2.Type = argon2.Type.ID,
    ) -> None:
        """

        Args:
            time_cost: Defines the amount of computation realized and
                therefore the execution time, given in number of iterations.
            memory_cost: Defines the memory usage, given in kibibytes.
            parallelism: Defines the number of parallel threads (*changes*
                the resulting hash value).
            hash_len: Length of the hash in bytes.
            salt_len: Length of random salt to be generated for each
                password.
            type: Argon2 type to use.  Only change for interoperability
                with legacy systems.

        """
        self._hasher = PasswordHasher(
            time_cost, memory_cost, parallelism, hash_len, salt_len, "utf-8", type
        )

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
        self,
        password: typing.Union[str, bytes],
        hash: typing.Union[str, bytes],
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
