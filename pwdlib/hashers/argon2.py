import re
from typing import ClassVar

try:
    import argon2.exceptions
    from argon2 import PasswordHasher
    from argon2._utils import _NAME_TO_TYPE
except ImportError as e:
    from ..exceptions import HasherNotAvailable

    raise HasherNotAvailable("argon2") from e

from .base import HasherProtocol, ensure_str

# Pattern for identifying and validating an Argon2 encoded hash, covering all currently
# supported type variants (i.e., `id`, `i`, `d`). Pattern uses deterministic matching,
# explicit anchors, and a non-greedy terminal quantifier to ensure linear run time
# relative to input hash length and resilience against catastrophic backtracking attacks.
ARGON2_ENCODED_HASH_REGEX: re.Pattern = re.compile(
    r"^\$argon2(?P<type>id|i|d)\$(?:v=(?P<version>\d+)\$)?"
    r"m=(?P<memory_cost>\d+),t=(?P<time_cost>\d+),p=(?P<parallelism>\d+)"
    r"(?:\$(?P<salt>[^$]+)(?:\$(?P<digest>.+?))?)?$"
)


class Argon2Hasher(HasherProtocol):
    name: ClassVar[str] = "argon2"

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
    def identify(cls, hash: str | bytes) -> bool:
        """
        Returns True if the supplied hash is a supported Argon2 hash.

        Checks if the supplied hash value is a valid and well-formed Argon2 encoded
        hash, safely converting bytes to a string if required.

        Args:
            hash (`str` | `bytes`): The hash value that should be evaluated.

        Returns:
            bool: Returns `True` if the supplied hash completely matches the Argon2
                regex pattern defined in `_ARGON2_ENCODED_HASH_REGEX` and presents a
                supported Argon2 variant, otherwise `False`. Any decode or type errors
                will also return `False`.
        """
        try:
            hash_str: str = ensure_str(hash)
            # This type guard is only necessary until the ensure_str function enforces
            # a stronger guarantee on its return type. At present, ensure_str will
            # simply reflect any type it receives that isn't a bytes object.
            if not isinstance(hash_str, str):
                return False
        except UnicodeDecodeError:
            return False  # Unable to decode the supplied hash.

        match = ARGON2_ENCODED_HASH_REGEX.fullmatch(hash_str)
        if match is None:
            return False  # Hash is not a valid or well-formed Argon2 hash.

        variant: str = match.group("type")  # ('id', 'd', 'i')
        type_name = f"{cls.name}{variant}"  # ('argon2id', 'argon2d', 'argon2i')
        return type_name in _NAME_TO_TYPE

    def hash(self, password: str | bytes, *, salt: bytes | None = None) -> str:
        return self._hasher.hash(password, salt=salt)

    def verify(self, password: str | bytes, hash: str | bytes) -> bool:
        try:
            return self._hasher.verify(hash, password)
        except (
            argon2.exceptions.VerificationError,
            argon2.exceptions.InvalidHashError,
        ):
            return False

    def check_needs_rehash(self, hash: str | bytes) -> bool:
        return self._hasher.check_needs_rehash(ensure_str(hash))
