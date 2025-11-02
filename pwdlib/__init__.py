"""Modern password hashing for Python"""

__version__ = "0.3.0"

from ._hash import PasswordHash

try:
    from . import zxcvbn
except ImportError:
    zxcvbn = None  # type: ignore

__all__ = ["PasswordHash", "zxcvbn"]
