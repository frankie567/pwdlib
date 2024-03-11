import typing

import pytest

from pwdlib.hashers.argon2 import Argon2Hasher

_PASSWORD = "herminetincture"

_HASHER = Argon2Hasher()
_HASH_STR = _HASHER.hash(_PASSWORD)
_HASH_BYTES = _HASH_STR.encode("ascii")


@pytest.fixture
def argon2_hasher() -> Argon2Hasher:
    return Argon2Hasher()


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
    assert Argon2Hasher.identify(hash) == result


def test_hash(argon2_hasher: Argon2Hasher) -> None:
    hash = argon2_hasher.hash("herminetincture")
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
    argon2_hasher: Argon2Hasher,
) -> None:
    assert argon2_hasher.verify(password, hash) == result
