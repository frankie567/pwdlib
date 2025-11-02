import pytest

from pwdlib import zxcvbn

pytestmark = pytest.mark.skipif(zxcvbn is None, reason="zxcvbn not available")


def test_zxcvbn_import():
    assert zxcvbn is not None
    assert hasattr(zxcvbn, "zxcvbn")


def test_zxcvbn_weak_password():
    result = zxcvbn.zxcvbn("password")
    assert int(result.score) < 3


def test_zxcvbn_strong_password():
    result = zxcvbn.zxcvbn("correct horse battery staple")
    assert int(result.score) >= 3


def test_zxcvbn_with_user_inputs():
    result = zxcvbn.zxcvbn("johndoe123", ["john", "doe"])
    assert int(result.score) < 3


def test_zxcvbn_result_structure():
    result = zxcvbn.zxcvbn("test123")
    assert hasattr(result, "guesses")
    assert hasattr(result, "guesses_log10")
    assert hasattr(result, "score")
    assert hasattr(result, "crack_times_seconds")
    assert hasattr(result, "crack_times_display")
    assert hasattr(result, "calc_time")


def test_zxcvbn_feedback():
    result = zxcvbn.zxcvbn("abc")
    assert result.feedback is not None
    assert hasattr(result.feedback, "warning")
    assert hasattr(result.feedback, "suggestions")
