import pytest

from pwdlib.zxcvbn import Entropy, Score, zxcvbn


@pytest.mark.parametrize(
    "password,expected_score",
    [
        ("password", Score.ZERO),
        ("correcthorsebatterystaple", Score.FOUR),
        ("Tr0ub4dour&3", Score.TWO),
    ],
)
def test_zxcvbn_score(password: str, expected_score: Score) -> None:
    result = zxcvbn(password)
    assert isinstance(result, Entropy)
    assert result.score == expected_score


def test_zxcvbn_with_user_inputs() -> None:
    password = "john1990"
    result_without_inputs = zxcvbn(password)
    result_with_inputs = zxcvbn(password, user_inputs=["john", "1990"])

    assert result_with_inputs.guesses <= result_without_inputs.guesses


def test_zxcvbn_entropy_attributes() -> None:
    result = zxcvbn("test_password_123")

    assert isinstance(result.guesses, int)
    assert isinstance(result.guesses_log10, float)
    assert hasattr(result, "crack_times_seconds")
    assert hasattr(result, "crack_times_display")
    assert hasattr(result, "score")
    assert hasattr(result, "feedback")
    assert isinstance(result.calc_time, int)
