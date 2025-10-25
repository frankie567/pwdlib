import pytest

from pwdlib.hashers.argon2 import Argon2Hasher

_PASSWORD = "herminetincture"

_HASHER = Argon2Hasher()
_HASH_STR = _HASHER.hash(_PASSWORD)
_HASH_BYTES = _HASH_STR.encode("ascii")
DEFAULT_ENCODING: str = "utf-8"

# Valid 256-bit Argon2 v1.3 hashes for testing, generated using the reference C
# implementation of Argon2. For example, to recreate ARGON2ID_HASH_STR:
# ❯ echo -n "herminetincture" | ./argon2 somesalt -id -m 16 -t 3 -p 4 -l 32
# Type:		Argon2id
# Iterations:	3
# Memory:		65536 KiB
# Parallelism:	4
# Hash:		1e79bb076a78a674e8de6439a859a71e347539906d557775077de3a1373f5d78
# Encoded:	$argon2id$v=19$m=65536,t=3,p=4$c29tZXNhbHQ$Hnm7B2p4pnTo3mQ5qFmnHjR1OZBtVXd1B33joTc/XXg
# 0.156 seconds
# Verification ok
ARGON2ID_HASH_STR: str = "$argon2id$v=19$m=65536,t=3,p=4$c29tZXNhbHQ$Hnm7B2p4pnTo3mQ5qFmnHjR1OZBtVXd1B33joTc/XXg"
ARGON2D_HASH_STR: str = "$argon2d$v=19$m=65536,t=3,p=4$c29tZXNhbHQ$P4FC8mhbA5awaolU7A6SOIr+vDJ+AvOcuryWUDzrdcI"
ARGON2I_HASH_STR: str = "$argon2i$v=19$m=65536,t=3,p=4$c29tZXNhbHQ$WJ38Rw8Y82z6oLJyORBTspC2tAIryIkb1harNHedEPM"
ARGON2ID_HASH_BYTES: bytes = ARGON2ID_HASH_STR.encode("utf-8")

ARGON2_MALFORMED_HASH: str = (
    "$argon2id$v=A&$m==,p=$c29tZXNhbHQ$arQWpIVsXmUQDj660XNQBCR3AeZaVN7ChRcM97sGDK4"
)
INVALID_UTF8_BYTES: bytes = b"\xc3\x28"  # UnicodeDecodeError when decoding with UTF-8


@pytest.fixture
def argon2_hasher() -> Argon2Hasher:
    return Argon2Hasher()


@pytest.mark.parametrize(
    "hash,result",
    [
        pytest.param(ARGON2ID_HASH_STR, True, id="identify(valid_argon2id_hash: str)"),
        pytest.param(ARGON2D_HASH_STR, True, id="identify(valid_argon2d_hash: str)"),
        pytest.param(ARGON2I_HASH_STR, True, id="identify(valid_argon2i_hash: str)"),
        pytest.param(
            ARGON2ID_HASH_BYTES, True, id="identify(valid_argon2id_hash: bytes)"
        ),
        pytest.param(
            ARGON2_MALFORMED_HASH, False, id="identify(malformed_argon2id_hash: str)"
        ),
        pytest.param(
            INVALID_UTF8_BYTES, False, id="identify(invalid_utf8_string: bytes)"
        ),
        pytest.param("", False, id="identify(empty_string: str)"),
    ],
)
def test_identify(hash: str | bytes, result: bool) -> None:
    assert Argon2Hasher.identify(hash) == result


def test_identify_large_hash() -> None:
    with open("tests/data/argon2id_large_hash", "rb") as large_hash_file:
        large_hash = large_hash_file.read()
    assert Argon2Hasher.identify(large_hash)


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
    hash: str | bytes,
    password: str,
    result: bool,
    argon2_hasher: Argon2Hasher,
) -> None:
    assert argon2_hasher.verify(password, hash) == result


@pytest.mark.parametrize(
    "invalid_value",
    [
        pytest.param(123, id="int"),
        pytest.param(None, id="None"),
        pytest.param([], id="list"),
        pytest.param({}, id="dict"),
    ],
)
def test_identify_invalid_type(invalid_value: object) -> None:
    with pytest.raises(TypeError, match="hash must be str or bytes"):
        Argon2Hasher.identify(invalid_value)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    "invalid_value",
    [
        pytest.param(123, id="int"),
        pytest.param(None, id="None"),
        pytest.param([], id="list"),
        pytest.param({}, id="dict"),
    ],
)
def test_hash_invalid_type(invalid_value: object, argon2_hasher: Argon2Hasher) -> None:
    with pytest.raises(TypeError, match="password must be str or bytes"):
        argon2_hasher.hash(invalid_value)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    "invalid_value",
    [
        pytest.param(123, id="int"),
        pytest.param(None, id="None"),
        pytest.param([], id="list"),
        pytest.param({}, id="dict"),
    ],
)
def test_verify_invalid_password_type(
    invalid_value: object, argon2_hasher: Argon2Hasher
) -> None:
    with pytest.raises(TypeError, match="password must be str or bytes"):
        argon2_hasher.verify(invalid_value, _HASH_STR)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    "invalid_value",
    [
        pytest.param(123, id="int"),
        pytest.param(None, id="None"),
        pytest.param([], id="list"),
        pytest.param({}, id="dict"),
    ],
)
def test_verify_invalid_hash_type(
    invalid_value: object, argon2_hasher: Argon2Hasher
) -> None:
    with pytest.raises(TypeError, match="hash must be str or bytes"):
        argon2_hasher.verify(_PASSWORD, invalid_value)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    "invalid_value",
    [
        pytest.param(123, id="int"),
        pytest.param(None, id="None"),
        pytest.param([], id="list"),
        pytest.param({}, id="dict"),
    ],
)
def test_check_needs_rehash_invalid_type(
    invalid_value: object, argon2_hasher: Argon2Hasher
) -> None:
    with pytest.raises(TypeError, match="hash must be str or bytes"):
        argon2_hasher.check_needs_rehash(invalid_value)  # type: ignore[arg-type]
