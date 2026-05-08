import base64
import binascii
import hashlib
import hmac
import os
import re

from .base import HasherProtocol, ensure_bytes, ensure_str, validate_str_or_bytes

# OWASP recommended parameters for scrypt
# https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html#scrypt
DEFAULT_N = 2**14  # CPU/memory cost parameter (16384)
DEFAULT_R = 8  # Block size parameter
DEFAULT_P = 1  # Parallelization parameter
DEFAULT_SALT_LEN = 16  # 16 bytes = 128 bits
DEFAULT_HASH_LEN = 64  # 64 bytes = 512 bits

# Pattern for identifying scrypt hashes
# Format: $scrypt$<N>$<salt>$<r>$<p>$<hash>
# Following Django's format: https://github.com/django/django/blob/main/django/contrib/auth/hashers.py
# Using standard base64 for salt and hash (can contain / and =)
SCRYPT_ENCODED_HASH_REGEX: re.Pattern = re.compile(
    r"^\$scrypt\$(\d+)\$([A-Za-z0-9+/=]+)\$(\d+)\$(\d+)\$([A-Za-z0-9+/=]+)$"
)


class ScryptHasher(HasherProtocol):
    """
    Scrypt password hasher using Python's builtin hashlib.scrypt.

    Follows OWASP recommendations for parameters:
    - N (CPU/memory cost): 2^14 (16384)
    - r (block size): 8
    - p (parallelization): 1

    Hash format: $scrypt$<N>$<salt>$<r>$<p>$<hash>
    All components are base64-encoded except N, r, p which are integers.
    """

    def __init__(
        self,
        n: int = DEFAULT_N,
        r: int = DEFAULT_R,
        p: int = DEFAULT_P,
        salt_len: int = DEFAULT_SALT_LEN,
        hash_len: int = DEFAULT_HASH_LEN,
    ) -> None:
        """
        Args:
            n: CPU/memory cost parameter (must be a power of 2, >= 2).
            r: Block size parameter.
            p: Parallelization parameter.
            salt_len: Length of the random salt in bytes.
            hash_len: Length of the derived key in bytes.
        """
        self.n = n
        self.r = r
        self.p = p
        self.salt_len = salt_len
        self.hash_len = hash_len

    @classmethod
    def identify(cls, hash: str | bytes) -> bool:
        """
        Identify if the given hash is a scrypt hash.

        Args:
            hash: The hash to identify.

        Returns:
            True if the hash matches the scrypt format, False otherwise.
        """
        validate_str_or_bytes(hash, "hash")
        try:
            hash_str = ensure_str(hash)
        except UnicodeDecodeError:
            return False
        return SCRYPT_ENCODED_HASH_REGEX.fullmatch(hash_str) is not None

    def hash(self, password: str | bytes, *, salt: bytes | None = None) -> str:
        """
        Hash a password using scrypt.

        Args:
            password: The password to hash.
            salt: Optional salt bytes. If None, a random salt will be generated.

        Returns:
            The encoded hash string in the format: $scrypt$<N>$<salt>$<r>$<p>$<hash>
        """
        validate_str_or_bytes(password, "password")

        if salt is None:
            salt = os.urandom(self.salt_len)
        elif len(salt) != self.salt_len:
            raise ValueError(
                f"salt must be exactly {self.salt_len} bytes long, got {len(salt)}"
            )

        # Generate the scrypt hash
        derived_key = hashlib.scrypt(
            password=ensure_bytes(password),
            salt=salt,
            n=self.n,
            r=self.r,
            p=self.p,
            dklen=self.hash_len,
        )

        # Encode salt and hash in standard base64 (with padding)
        salt_b64 = base64.b64encode(salt).decode("ascii")
        hash_b64 = base64.b64encode(derived_key).decode("ascii")

        return f"$scrypt${self.n}${salt_b64}${self.r}${self.p}${hash_b64}"

    def verify(self, password: str | bytes, hash: str | bytes) -> bool:
        """
        Verify a password against a scrypt hash.

        Args:
            password: The password to verify.
            hash: The stored hash to verify against.

        Returns:
            True if the password matches the hash, False otherwise.
        """
        validate_str_or_bytes(password, "password")
        validate_str_or_bytes(hash, "hash")

        try:
            hash_str = ensure_str(hash)
        except UnicodeDecodeError:
            return False

        match = SCRYPT_ENCODED_HASH_REGEX.fullmatch(hash_str)
        if match is None:
            return False

        try:
            n = int(match.group(1))
            salt_b64 = match.group(2)
            r = int(match.group(3))
            p = int(match.group(4))
            expected_hash_b64 = match.group(5)

            # Decode salt and expected hash (standard base64)
            salt = base64.b64decode(salt_b64)
            expected_hash = base64.b64decode(expected_hash_b64)

            # Recompute the hash with the same parameters
            derived_key = hashlib.scrypt(
                password=ensure_bytes(password),
                salt=salt,
                n=n,
                r=r,
                p=p,
                dklen=len(expected_hash),
            )

            # Use constant-time comparison
            return hmac.compare_digest(derived_key, expected_hash)
        except (ValueError, TypeError, binascii.Error):
            return False

    def check_needs_rehash(self, hash: str | bytes) -> bool:
        """
        Check if a hash needs to be rehashed with the current parameters.

        Args:
            hash: The hash to check.

        Returns:
            True if the hash parameters differ from the current configuration.
        """
        validate_str_or_bytes(hash, "hash")

        try:
            hash_str = ensure_str(hash)
        except UnicodeDecodeError:
            return True

        match = SCRYPT_ENCODED_HASH_REGEX.fullmatch(hash_str)
        if match is None:
            return True

        try:
            n = int(match.group(1))
            r = int(match.group(3))
            p = int(match.group(4))

            return n != self.n or r != self.r or p != self.p
        except (ValueError, TypeError):
            return True
