import typing

import pytest

from pwdlib.hashers.bcrypt import BcryptHasher

_PASSWORD = "herminetincture"

_HASHER = BcryptHasher()
_HASH_STR = _HASHER.hash(_PASSWORD)
_HASH_BYTES = _HASH_STR.encode("ascii")


@pytest.fixture
def bcrypt_hasher() -> BcryptHasher:
    return BcryptHasher()


@pytest.mark.parametrize(
    "hash,result",
    [
        (_HASH_STR, True),
        (_HASH_BYTES, True),
        ("INVALID_HASH", False),
        (b"INVALID_HASH", False),
    ],
)
def test_identify(hash: typing.Union[str, bytes], result: bool) -> None:
    assert BcryptHasher.identify(hash) == result


def test_hash(bcrypt_hasher: BcryptHasher) -> None:
    hash = bcrypt_hasher.hash("herminetincture")
    assert isinstance(hash, str)


@pytest.mark.parametrize(
    "hash,password,result",
    [
        (_HASH_STR, _PASSWORD, True),
        (_HASH_BYTES, _PASSWORD, True),
        (_HASH_STR, "INVALID_PASSWORD", False),
        (_HASH_BYTES, "INVALID_PASSWORD", False),
    ],
)
def test_verify(
    hash: typing.Union[str, bytes],
    password: str,
    result: bool,
    bcrypt_hasher: BcryptHasher,
) -> None:
    assert bcrypt_hasher.verify(password, hash) == result


def test_check_needs_rehash(bcrypt_hasher: BcryptHasher) -> None:
    assert not bcrypt_hasher.check_needs_rehash(_HASH_STR)
    assert not bcrypt_hasher.check_needs_rehash(_HASH_BYTES)
    assert bcrypt_hasher.check_needs_rehash("INVALID_HASH")
    assert bcrypt_hasher.check_needs_rehash(b"INVALID_HASH")

    bcrypt_hasher_different_rounds = BcryptHasher(rounds=10)
    hash = bcrypt_hasher_different_rounds.hash("herminetincture")
    assert bcrypt_hasher.check_needs_rehash(hash)

    bcrypt_hasher_different_prefix = BcryptHasher(prefix="2a")
    hash = bcrypt_hasher_different_prefix.hash("herminetincture")
    assert bcrypt_hasher.check_needs_rehash(hash)
