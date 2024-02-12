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
        """
        return self.current_hasher.hash(password, salt=salt)

    def verify(
        self, hash: typing.Union[str, bytes], password: typing.Union[str, bytes]
    ) -> bool:
        """
        Verifies if a password matches a given hash.

        Args:
            hash: The hash to be verified.
            password: The password to be checked.

        Returns:
            True if the password matches the hash, False otherwise.

        Raises:
            exceptions.UnknownHashError: If the hash is not recognized by any of the hashers.
        """
        for hasher in self.hashers:
            if hasher.identify(hash):
                return hasher.verify(hash, password)
        raise exceptions.UnknownHashError(hash)

    def verify_and_update(
        self, hash: typing.Union[str, bytes], password: typing.Union[str, bytes]
    ) -> typing.Tuple[bool, typing.Union[str, None]]:
        """
        Verifies if a password matches a given hash and updates the hash if necessary.

        Args:
            hash: The hash to be verified.
            password: The password to be checked.

        Returns:
            A tuple containing a boolean indicating if the password matches the hash,
                and an updated hash if the current hasher or the hash itself needs to be updated.

        Raises:
            exceptions.UnknownHashError: If the hash is not recognized by any of the hashers.
        """
        for hasher in self.hashers:
            if hasher.identify(hash):
                if not hasher.verify(hash, password):
                    return False, None
                else:
                    updated_hash: typing.Union[str, None] = None
                    if hasher != self.current_hasher or hasher.check_needs_rehash(hash):
                        updated_hash = self.current_hasher.hash(password)
                    return True, updated_hash
        raise exceptions.UnknownHashError(hash)
