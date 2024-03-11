import typing

from . import exceptions
from .hashers import HasherProtocol


class PasswordHash:
    """
    Represents a password hashing utility.
    """

    def __init__(self, hashers: typing.Sequence[HasherProtocol]) -> None:
        """
        Args:
            hashers: A sequence of hashers to be used for password hashing.

        Raises:
            AssertionError: If no hashers are specified.
        """
        assert len(hashers) > 0, "You must specify at least one hasher."
        self.hashers = hashers
        self.current_hasher = hashers[0]

    @classmethod
    def recommended(cls) -> "PasswordHash":
        """
        Returns a PasswordHash instance with recommended hashers.

        Currently, the hasher is Argon2 with default parameters.

        Examples:
            >>> password_hash = PasswordHash.recommended()
            >>> hash = password_hash.hash("herminetincture")
            >>> password_hash.verify(hash, "herminetincture")
            True
        """
        from .hashers.argon2 import Argon2Hasher

        return cls((Argon2Hasher(),))

    def hash(
        self,
        password: typing.Union[str, bytes],
        *,
        salt: typing.Union[bytes, None] = None,
    ) -> str:
        """
        Hashes a password using the current hasher.

        Args:
            password: The password to be hashed.
            salt: The salt to be used for hashing. Defaults to None.

        Returns:
            The hashed password.

        Examples:
            >>> hash = password_hash.hash("herminetincture")
        """
        return self.current_hasher.hash(password, salt=salt)

    def verify(
        self, password: typing.Union[str, bytes], hash: typing.Union[str, bytes]
    ) -> bool:
        """
        Verifies if a password matches a given hash.

        Args:
            password: The password to be checked.
            hash: The hash to be verified.

        Returns:
            True if the password matches the hash, False otherwise.

        Raises:
            exceptions.UnknownHashError: If the hash is not recognized by any of the hashers.

        Examples:
            >>> password_hash.verify("herminetincture", hash)
            True

            >>> password_hash.verify("INVALID_PASSWORD", hash)
            False
        """
        for hasher in self.hashers:
            if hasher.identify(hash):
                return hasher.verify(password, hash)
        raise exceptions.UnknownHashError(hash)

    def verify_and_update(
        self, password: typing.Union[str, bytes], hash: typing.Union[str, bytes]
    ) -> typing.Tuple[bool, typing.Union[str, None]]:
        """
        Verifies if a password matches a given hash and updates the hash if necessary.

        Args:
            password: The password to be checked.
            hash: The hash to be verified.

        Returns:
            A tuple containing a boolean indicating if the password matches the hash,
                and an updated hash if the current hasher or the hash itself needs to be updated.

        Raises:
            exceptions.UnknownHashError: If the hash is not recognized by any of the hashers.

        Examples:
            >>> valid, updated_hash = password_hash.verify_and_update("herminetincture", hash)
        """
        for hasher in self.hashers:
            if hasher.identify(hash):
                if not hasher.verify(password, hash):
                    return False, None
                else:
                    updated_hash: typing.Union[str, None] = None
                    if hasher != self.current_hasher or hasher.check_needs_rehash(hash):
                        updated_hash = self.current_hasher.hash(password)
                    return True, updated_hash
        raise exceptions.UnknownHashError(hash)
