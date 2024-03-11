import typing

import pytest

from pwdlib import PasswordHash, exceptions
from pwdlib.hashers.argon2 import Argon2Hasher
from pwdlib.hashers.bcrypt import BcryptHasher

_PASSWORD = "herminetincture"

_ARGON2_HASHER = Argon2Hasher()
_ARGON2_HASH_STR = _ARGON2_HASHER.hash(_PASSWORD)

_BCRYPT_HASHER = BcryptHasher()
_BCRYPT_HASH_STR = _BCRYPT_HASHER.hash(_PASSWORD)


@pytest.fixture
def password_hash() -> PasswordHash:
    return PasswordHash((Argon2Hasher(), BcryptHasher()))


def test_recommended() -> None:
    password_hash = PasswordHash.recommended()
    assert len(password_hash.hashers) == 1
    assert isinstance(password_hash.current_hasher, Argon2Hasher)


def test_hash(password_hash: PasswordHash) -> None:
    hash = password_hash.hash("herminetincture")
    assert isinstance(hash, str)
    assert password_hash.current_hasher.identify(hash)


@pytest.mark.parametrize(
    "hash,password,result",
    [
        (_ARGON2_HASH_STR, _PASSWORD, True),
        (_ARGON2_HASH_STR, "INVALID_PASSWORD", False),
        (_BCRYPT_HASH_STR, _PASSWORD, True),
        (_BCRYPT_HASH_STR, "INVALID_PASSWORD", False),
    ],
)
def test_verify(
    hash: typing.Union[str, bytes],
    password: str,
    result: bool,
    password_hash: PasswordHash,
) -> None:
    assert password_hash.verify(password, hash) == result


def test_verify_unknown_hash(password_hash: PasswordHash) -> None:
    with pytest.raises(exceptions.UnknownHashError):
        password_hash.verify("INVALID_HASH", _PASSWORD)


@pytest.mark.parametrize(
    "hash,password,result,has_updated_hash",
    [
        (_ARGON2_HASH_STR, _PASSWORD, True, False),
        (_ARGON2_HASH_STR, "INVALID_PASSWORD", False, False),
        (_BCRYPT_HASH_STR, _PASSWORD, True, True),
        (_BCRYPT_HASH_STR, "INVALID_PASSWORD", False, False),
    ],
)
def test_verify_and_update(
    hash: typing.Union[str, bytes],
    password: str,
    result: bool,
    has_updated_hash: bool,
    password_hash: PasswordHash,
) -> None:
    valid, updated_hash = password_hash.verify_and_update(password, hash)
    assert valid == result
    assert updated_hash is not None if has_updated_hash else updated_hash is None
    if updated_hash is not None:
        assert password_hash.current_hasher.identify(updated_hash)


def test_verify_and_update_unknown_hash(password_hash: PasswordHash) -> None:
    with pytest.raises(exceptions.UnknownHashError):
        password_hash.verify_and_update(_PASSWORD, "INVALID_HASH")
