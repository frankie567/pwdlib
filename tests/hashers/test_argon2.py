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
ARGON2ID_HASH_BYTES: bytes = ARGON2ID_HASH_STR.encode(DEFAULT_ENCODING)

# Invalid or malformed Argon2 hashes for testing.
ARGON2_MALFORMED_HASH: str = (
    "$argon2id$v=A&$m==,p=$c29tZXNhbHQ$arQWpIVsXmUQDj660XNQBCR3AeZaVN7ChRcM97sGDK4"
)
INVALID_UTF8_BYTES: bytes = b"\xc3\x28"  # UnicodeDecodeError when decoding with UTF-8


@pytest.fixture
def argon2_hasher() -> Argon2Hasher:
    return Argon2Hasher()


@pytest.fixture(scope="module")
def argon2id_large_hash() -> bytes:
    """Returns a very large (~174KB) but well-formed Argon2id encoded hash."""
    with open("tests/data/argon2id_large_hash", "rb") as large_hash:
        return large_hash.read()


@pytest.mark.parametrize(
    "hash, expected_result",
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
        pytest.param(12, False, id="identify(invalid_int: int)"),
        pytest.param("", False, id="identify(empty_string: str)"),
    ],
)
def test_identify(hash: str | bytes, expected_result: bool) -> None:
    """All valid Argon2 hashes and variants are supported."""
    assert Argon2Hasher.identify(hash) == expected_result


def test_identify_large_hash(argon2id_large_hash) -> None:
    """An extremely large but well-formed Argon2id hash is supported."""
    assert Argon2Hasher.identify(argon2id_large_hash)


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
