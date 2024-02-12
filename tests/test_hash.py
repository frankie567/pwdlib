import typing

import pytest

from pwdlib import PasswordHash, exceptions
from pwdlib.hashers.argon2 import Argon2Hasher

_PASSWORD = "herminetincture"

_ARGON2_HASHER = Argon2Hasher()
_ARGON2_HASH_STR = _ARGON2_HASHER.hash(_PASSWORD)


@pytest.fixture
def password_hash() -> PasswordHash:
    return PasswordHash((Argon2Hasher(),))


def test_hash(password_hash: PasswordHash) -> None:
    hash = password_hash.hash("herminetincture")
    assert isinstance(hash, str)
    assert password_hash.current_hasher.identify(hash)


@pytest.mark.parametrize(
    "hash,password,result",
    [
        (_ARGON2_HASH_STR, _PASSWORD, True),
        (_ARGON2_HASH_STR, "INVALID_PASSWORD", False),
    ],
)
def test_verify(
    hash: typing.Union[str, bytes],
    password: str,
    result: bool,
    password_hash: PasswordHash,
) -> None:
    assert password_hash.verify(hash, password) == result


def test_verify_unknown_hash(password_hash: PasswordHash) -> None:
    with pytest.raises(exceptions.UnknownHashError):
        assert password_hash.verify("INVALID_HASH", _PASSWORD)
