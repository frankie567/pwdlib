import typing

from . import exceptions
from .hashers import HasherProtocol


class PasswordHash:
    def __init__(self, hashers: typing.Sequence[HasherProtocol]) -> None:
        assert len(hashers) > 0, "You must specify at least one hasher."
        self.hashers = hashers
        self.current_hasher = hashers[0]

    def hash(
        self,
        password: typing.Union[str, bytes],
        *,
        salt: typing.Union[bytes, None] = None,
    ) -> str:
        return self.current_hasher.hash(password, salt=salt)

    def verify(
        self, hash: typing.Union[str, bytes], password: typing.Union[str, bytes]
    ) -> bool:
        for hasher in self.hashers:
            if hasher.identify(hash):
                return hasher.verify(hash, password)
        raise exceptions.UnknownHashError(hash)

    def verify_and_update(
        self, hash: typing.Union[str, bytes], password: typing.Union[str, bytes]
    ) -> typing.Tuple[bool, typing.Union[str, None]]:
        for hasher in self.hashers:
            if hasher.identify(hash):
                if not hasher.verify(hash, password):
                    return False, None
                else:
                    updated_hash: typing.Union[str, None] = None
                    if hasher != self.current_hasher or hasher.check_needs_rehash(hash):
                        updated_hash = hasher.hash(password)
                    return True, updated_hash
        raise exceptions.UnknownHashError(hash)
