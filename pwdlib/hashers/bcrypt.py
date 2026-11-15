import re
import typing

try:
    import bcrypt
except ImportError as e:  # pragma: no cover
    from ..exceptions import HasherNotAvailable

    raise HasherNotAvailable("bcrypt") from e

from ..exceptions import HashGenerationError, HashVerificationError
from .base import HasherProtocol, ensure_bytes, ensure_str, validate_str_or_bytes

_IDENTIFY_REGEX = (
    r"^\$(?P<prefix>2[abxy])\$(?P<rounds>\d{2})"
    r"\$(?P<salt>[A-Za-z0-9+/.]{22})(?P<hash>[A-Za-z0-9+/.]{31})$"
)


def _match_regex_hash(hash: str | bytes) -> re.Match[str] | None:
    return re.match(_IDENTIFY_REGEX, ensure_str(hash))


class BcryptHasher(HasherProtocol):
    def __init__(
        self, rounds: int = 12, prefix: typing.Literal["2a", "2b"] = "2b"
    ) -> None:
        """
        Args:
            rounds: The number of rounds to use for hashing.
            prefix: The prefix to use for hashing.
        """
        self.rounds = rounds
        self.prefix = prefix.encode("utf-8")

    @classmethod
    def identify(cls, hash: str | bytes) -> bool:
        validate_str_or_bytes(hash, "hash")
        return _match_regex_hash(hash) is not None

    def hash(self, password: str | bytes, *, salt: bytes | None = None) -> str:
        """
        Hashes a password using bcrypt.

        Raises:
            HashGenerationError: If the backend fails to generate the salt or hash.
        """
        validate_str_or_bytes(password, "password")
        password_bytes = ensure_bytes(password)
        try:
            if salt is None:
                salt = bcrypt.gensalt(self.rounds, self.prefix)
            hashed = bcrypt.hashpw(password_bytes, salt)
        except ValueError as e:
            raise HashGenerationError() from e
        return ensure_str(hashed)

    def verify(self, password: str | bytes, hash: str | bytes) -> bool:
        validate_str_or_bytes(password, "password")
        validate_str_or_bytes(hash, "hash")
        password_bytes = ensure_bytes(password)
        hash_bytes = ensure_bytes(hash)
        try:
            return bcrypt.checkpw(password_bytes, hash_bytes)
        except ValueError as e:
            raise HashVerificationError() from e

    def check_needs_rehash(self, hash: str | bytes) -> bool:
        validate_str_or_bytes(hash, "hash")
        _hash_match = _match_regex_hash(hash)
        if _hash_match is None:
            return True

        return int(_hash_match.group("rounds")) != self.rounds or _hash_match.group(
            "prefix"
        ) != self.prefix.decode("utf-8")
