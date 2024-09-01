from urllib import parse

import pytest

from pwdlib import totp


def test_otp_key_url():
    t = totp.TOTP(key=bytes([0, 0, 0, 0, 0, 0, 0, 0, 0, 0]))
    parts = t.to_url("foo@example.com").split("?", 1)
    assert parts[0] == "otpauth://totp/foo%40example.com"
    qs = parse.parse_qs(parts[1])
    assert qs == {
        "secret": ["AAAAAAAAAAAAAAAA"],
        "algorithm": ["SHA1"],
        "digits": ["6"],
        "period": ["30"],
    }


def test_otp_key_url_with_issuer():
    t = totp.TOTP(key=bytes([0, 0, 0, 0, 0, 0, 0, 0, 0, 0]))
    parts = t.to_url("foo@example.com", issuer="Yoyodyne Systems").split("?", 1)
    assert parts[0] == "otpauth://totp/Yoyodyne%20Systems:foo%40example.com"
    qs = parse.parse_qs(parts[1])
    assert qs == {
        "secret": ["AAAAAAAAAAAAAAAA"],
        "algorithm": ["SHA1"],
        "digits": ["6"],
        "period": ["30"],
        "issuer": ["Yoyodyne Systems"],
    }


def test_serialisation():
    t1 = totp.TOTP(key=bytes(range(0, 10)), alg="sha256", digits=10, period=60)
    d = t1.to_dict()
    assert d == {
        "alg": "sha256",
        "digits": 10,
        "key": "AAECAwQFBgcICQ==",
        "period": 60,
    }
    t2 = totp.TOTP.from_dict(d)
    assert t1.key == t2.key
    assert t1.alg == t2.alg
    assert t1.digits == t2.digits
    assert t1.period == t2.period


def test_bad_algorithm():
    with pytest.raises(totp.UnknownHashAlgorithmError):
        totp.TOTP(alg="foo")


def test_key_generated():
    t = totp.TOTP()
    assert isinstance(t.key, bytes)


def test_validity():
    t = totp.TOTP()
    assert t.check(t.generate())


def test_failure():
    t = totp.TOTP(period=5)
    now = 123456780
    otp = t.generate(now=now)
    assert t.check(otp, window=1, now=now)
    # Just shy of the window...
    assert t.check(otp, window=1, now=now + 4)
    # Past the window.
    assert not t.check(otp, window=1, now=now + 5)


def check_vector(key: bytes, alg: str, now: int, expected: str):
    assert totp.TOTP(key=key, alg=alg, digits=8, period=30).generate(now) == expected


@pytest.mark.parametrize(
    "now,expected",
    [
        (59, "94287082"),
        (1111111109, "07081804"),
        (1111111111, "14050471"),
        (1234567890, "89005924"),
        (2000000000, "69279037"),
        (20000000000, "65353130"),
    ],
)
def test_sha1_vectors(now: int, expected: str):
    check_vector(
        b"12345678901234567890",
        "sha1",
        now,
        expected,
    )


@pytest.mark.parametrize(
    "now,expected",
    [
        (59, "46119246"),
        (1111111109, "68084774"),
        (1111111111, "67062674"),
        (1234567890, "91819424"),
        (2000000000, "90698825"),
        (20000000000, "77737706"),
    ],
)
def test_sha256_vectors(now: int, expected: str):
    check_vector(
        b"12345678901234567890123456789012",
        "sha256",
        now,
        expected,
    )


@pytest.mark.parametrize(
    "now,expected",
    [
        (59, "90693936"),
        (1111111109, "25091201"),
        (1111111111, "99943326"),
        (1234567890, "93441116"),
        (2000000000, "38618901"),
        (20000000000, "47863826"),
    ],
)
def test_sha512_vectors(now: int, expected: str):
    check_vector(
        b"1234567890123456789012345678901234567890123456789012345678901234",
        "sha512",
        now,
        expected,
    )
