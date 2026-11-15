from importlib.metadata import version
from unittest.mock import patch

import pytest
from argon2 import PasswordHasher
from argon2.exceptions import HashingError, InvalidHashError, VerificationError

from pwdlib import PasswordHash, exceptions
from pwdlib.hashers import HasherProtocol
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
    "hasher,salt,error",
    [
        pytest.param(Argon2Hasher(), b"x", HashingError, id="argon2-invalid-salt"),
        pytest.param(BcryptHasher(), b"x", ValueError, id="bcrypt-invalid-salt"),
        pytest.param(BcryptHasher(rounds=3), None, ValueError, id="bcrypt-gensalt"),
    ],
)
def test_hash_generation_error(
    hasher: HasherProtocol, salt: bytes | None, error: type[Exception]
) -> None:
    password_hash = PasswordHash((hasher,))
    with pytest.raises(exceptions.HashGenerationError) as exc_info:
        password_hash.hash(_PASSWORD, salt=salt)
    assert type(exc_info.value.__cause__) is error


@pytest.mark.skipif(
    int(version("bcrypt").split(".", 1)[0]) < 5,
    reason="bcrypt 5 introduced the rejection of passwords longer than 72 bytes",
)
def test_bcrypt_hash_generation_rejects_long_password() -> None:
    argon2_hasher = Argon2Hasher()
    password_hash = PasswordHash((BcryptHasher(rounds=4), argon2_hasher))
    password = "é" * 36 + "x"
    stored = argon2_hasher.hash(password)

    with pytest.raises(exceptions.HashGenerationError) as exc_info:
        password_hash.hash(password)
    assert isinstance(exc_info.value.__cause__, ValueError)

    with pytest.raises(exceptions.HashGenerationError) as exc_info:
        password_hash.verify_and_update(password, stored)
    assert isinstance(exc_info.value.__cause__, ValueError)


def test_bcrypt_hash_leaves_encoding_error_unchanged() -> None:
    with pytest.raises(UnicodeEncodeError):
        _BCRYPT_HASHER.hash("\ud800")


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
    hash: str | bytes,
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
    hash: str | bytes,
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


@pytest.mark.parametrize("method", ["verify", "verify_and_update"])
@pytest.mark.parametrize(
    "hash,error",
    [
        pytest.param(
            "$argon2id$v=19$m=65536,t=3,p=4$invalid$invalid",
            VerificationError,
            id="argon2",
        ),
        pytest.param(f"$2b$99${_BCRYPT_HASH_STR[7:]}", ValueError, id="bcrypt"),
    ],
)
def test_verify_malformed_hash(
    method: str, hash: str, error: type[Exception], password_hash: PasswordHash
) -> None:
    with pytest.raises(exceptions.HashVerificationError) as exc_info:
        getattr(password_hash, method)(_PASSWORD, hash)
    assert type(exc_info.value.__cause__) is error


@pytest.mark.parametrize("method", ["verify", "verify_and_update"])
@pytest.mark.parametrize("error", [VerificationError, InvalidHashError])
def test_verify_argon2_backend_error(
    method: str, error: type[Exception], password_hash: PasswordHash
) -> None:
    backend_error = error()
    with (
        patch.object(PasswordHasher, "verify", side_effect=backend_error),
        pytest.raises(exceptions.HashVerificationError) as exc_info,
    ):
        getattr(password_hash, method)(_PASSWORD, _ARGON2_HASH_STR)
    assert exc_info.value.__cause__ is backend_error


@pytest.mark.parametrize(
    "invalid_value",
    [
        pytest.param(123, id="int"),
        pytest.param(None, id="None"),
        pytest.param([], id="list"),
        pytest.param({}, id="dict"),
    ],
)
def test_invalid_type(invalid_value: object, password_hash: PasswordHash) -> None:
    with pytest.raises(TypeError, match="password must be str or bytes"):
        password_hash.hash(invalid_value)  # ty: ignore[invalid-argument-type]
    with pytest.raises(TypeError, match="password must be str or bytes"):
        password_hash.verify(invalid_value, _ARGON2_HASH_STR)  # ty: ignore[invalid-argument-type]
    with pytest.raises(TypeError, match="hash must be str or bytes"):
        password_hash.verify(_PASSWORD, invalid_value)  # ty: ignore[invalid-argument-type]
    with pytest.raises(TypeError, match="password must be str or bytes"):
        password_hash.verify_and_update(invalid_value, _ARGON2_HASH_STR)  # ty: ignore[invalid-argument-type]
    with pytest.raises(TypeError, match="hash must be str or bytes"):
        password_hash.verify_and_update(_PASSWORD, invalid_value)  # ty: ignore[invalid-argument-type]
