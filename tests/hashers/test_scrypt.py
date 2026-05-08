import base64
import hashlib
import pytest

from pwdlib.hashers.scrypt import ScryptHasher

_PASSWORD = "testpassword123"

_HASHER = ScryptHasher()
_HASH_STR = _HASHER.hash(_PASSWORD)
_HASH_BYTES = _HASH_STR.encode("ascii")


@pytest.fixture
def scrypt_hasher() -> ScryptHasher:
    return ScryptHasher()


@pytest.fixture
def scrypt_hasher_custom_params() -> ScryptHasher:
    return ScryptHasher(n=2**10, r=4, p=1)


@pytest.mark.parametrize(
    "hash,result",
    [
        pytest.param(_HASH_STR, True, id="identify(valid_scrypt_hash: str)"),
        pytest.param(_HASH_BYTES, True, id="identify(valid_scrypt_hash: bytes)"),
        pytest.param("$scrypt$16384$invalid$8$1", False, id="identify(invalid_scrypt_hash: wrong_format)"),
        pytest.param("$bcrypt$12$N9Zh0y3G.3yBxRlA57Wo1O3TEmZBx2SF5N2P0t3jOTuK./Ko8dH3u", False, id="identify(bcrypt_hash)"),
        pytest.param("$argon2id$v=19$m=65536,t=3,p=4$c29tZXNhbHQ$Hnm7B2p4pnTo3mQ5qFmnHjR1OZBtVXd1B33joTc/XXg", False, id="identify(argon2_hash)"),
        pytest.param("", False, id="identify(empty_string: str)"),
        pytest.param(b"", False, id="identify(empty_string: bytes)"),
    ],
)
def test_identify(hash: str | bytes, result: bool) -> None:
    assert ScryptHasher.identify(hash) == result


def test_hash(scrypt_hasher: ScryptHasher) -> None:
    hash = scrypt_hasher.hash("testpassword123")
    assert isinstance(hash, str)
    assert hash.startswith("$scrypt$")
    assert ScryptHasher.identify(hash)


def test_hash_with_custom_salt(scrypt_hasher: ScryptHasher) -> None:
    custom_salt = b"customsalt123456"
    hash = scrypt_hasher.hash(_PASSWORD, salt=custom_salt)
    assert isinstance(hash, str)
    assert ScryptHasher.identify(hash)


def test_hash_deterministic_with_same_salt(scrypt_hasher: ScryptHasher) -> None:
    custom_salt = b"fixedsalt12345678"
    hash1 = scrypt_hasher.hash(_PASSWORD, salt=custom_salt)
    hash2 = scrypt_hasher.hash(_PASSWORD, salt=custom_salt)
    assert hash1 == hash2


def test_hash_different_with_different_salt(scrypt_hasher: ScryptHasher) -> None:
    hash1 = scrypt_hasher.hash(_PASSWORD, salt=b"salt1")
    hash2 = scrypt_hasher.hash(_PASSWORD, salt=b"salt2")
    assert hash1 != hash2


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
    hash: str | bytes,
    password: str,
    result: bool,
    scrypt_hasher: ScryptHasher,
) -> None:
    assert scrypt_hasher.verify(password, hash) == result


def test_verify_with_custom_params(scrypt_hasher_custom_params: ScryptHasher) -> None:
    hash = scrypt_hasher_custom_params.hash(_PASSWORD)
    assert scrypt_hasher_custom_params.verify(_PASSWORD, hash)
    assert not scrypt_hasher_custom_params.verify("wrong", hash)


def test_verify_invalid_hash_format(scrypt_hasher: ScryptHasher) -> None:
    assert not scrypt_hasher.verify(_PASSWORD, "INVALID_HASH")
    assert not scrypt_hasher.verify(_PASSWORD, b"INVALID_HASH")


def test_check_needs_rehash(scrypt_hasher: ScryptHasher) -> None:
    # Hash with default params should not need rehash
    hash = scrypt_hasher.hash(_PASSWORD)
    assert not scrypt_hasher.check_needs_rehash(hash)
    assert not scrypt_hasher.check_needs_rehash(hash.encode("ascii"))


def test_check_needs_rehash_different_params(scrypt_hasher: ScryptHasher, scrypt_hasher_custom_params: ScryptHasher) -> None:
    # Hash with custom params should need rehash when checked with default params
    hash = scrypt_hasher_custom_params.hash(_PASSWORD)
    assert scrypt_hasher.check_needs_rehash(hash)


def test_check_needs_rehash_invalid_format(scrypt_hasher: ScryptHasher) -> None:
    assert scrypt_hasher.check_needs_rehash("INVALID_HASH")
    assert scrypt_hasher.check_needs_rehash(b"INVALID_HASH")


@pytest.mark.parametrize(
    "invalid_value",
    [
        pytest.param(123, id="int"),
        pytest.param(None, id="None"),
        pytest.param([], id="list"),
        pytest.param({}, id="dict"),
    ],
)
def test_invalid_type(invalid_value: object, scrypt_hasher: ScryptHasher) -> None:
    with pytest.raises(TypeError, match="hash must be str or bytes"):
        ScryptHasher.identify(invalid_value)  # type: ignore[arg-type]
    with pytest.raises(TypeError, match="password must be str or bytes"):
        scrypt_hasher.hash(invalid_value)  # type: ignore[arg-type]
    with pytest.raises(TypeError, match="password must be str or bytes"):
        scrypt_hasher.verify(invalid_value, _HASH_STR)  # type: ignore[arg-type]
    with pytest.raises(TypeError, match="hash must be str or bytes"):
        scrypt_hasher.verify(_PASSWORD, invalid_value)  # type: ignore[arg-type]
    with pytest.raises(TypeError, match="hash must be str or bytes"):
        scrypt_hasher.check_needs_rehash(invalid_value)  # type: ignore[arg-type]


def test_hash_format(scrypt_hasher: ScryptHasher) -> None:
    """Test that the hash format matches the expected pattern."""
    hash = scrypt_hasher.hash(_PASSWORD)
    parts = hash.split("$")

    # Format: $scrypt$N$salt$r$p$hash (Django-style)
    # Note: parts[0] is empty, parts[1] is 'scrypt', parts[2] is N,
    # parts[3] is salt (base64), parts[4] is r, parts[5] is p, parts[6] is hash (base64)
    assert len(parts) == 7
    assert parts[0] == ""
    assert parts[1] == "scrypt"
    assert parts[2] == str(scrypt_hasher.n)  # N parameter
    assert parts[4] == str(scrypt_hasher.r)  # r parameter
    assert parts[5] == str(scrypt_hasher.p)  # p parameter

    # Check that salt and hash are valid base64
    salt_b64 = parts[3]
    hash_b64 = parts[6]

    # The salt should be base64 decodable
    salt = base64.b64decode(salt_b64)
    assert len(salt) == scrypt_hasher.salt_len


def test_verify_manual_hash(scrypt_hasher: ScryptHasher) -> None:
    """Test verification with a manually constructed hash."""
    password = "test123"
    salt = b"manuelsalt1234"

    # Create hash manually
    derived_key = hashlib.scrypt(
        password=password.encode("utf-8"),
        salt=salt,
        n=scrypt_hasher.n,
        r=scrypt_hasher.r,
        p=scrypt_hasher.p,
        dklen=scrypt_hasher.hash_len,
    )

    # Use standard base64 with padding (Django-style)
    salt_b64 = base64.b64encode(salt).decode("ascii")
    hash_b64 = base64.b64encode(derived_key).decode("ascii")
    manual_hash = f"$scrypt${scrypt_hasher.n}${salt_b64}${scrypt_hasher.r}${scrypt_hasher.p}${hash_b64}"

    assert scrypt_hasher.verify(password, manual_hash)
    assert not scrypt_hasher.verify("wrong", manual_hash)
