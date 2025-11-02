# Guide

This will guide you through the basic features of `pwdlib`.

## Password hashing

To manage password hashes, `pwdlib` exposes the [`PasswordHash`](./reference/pwdlib.md#pwdlib.PasswordHash) class. The difference with a "plain" hash algorithm helper is that it supports **multiple algorithms**. Why it's useful?

Currently, the safest and recommended algorithm for password hashing is [Argon2](https://en.wikipedia.org/wiki/Argon2). But it's probable that in the coming years, a new and even safer algorithm emerges. Thanks to a wrapper like [`PasswordHash`](./reference/pwdlib.md#pwdlib.PasswordHash), we'll be able to verify hash generated with the older algorithm while upgrading them to the newer one.

This is how you create an instance of [`PasswordHash`](./reference/pwdlib.md#pwdlib.PasswordHash) with Argon2 and Bcrypt support:

```py
from pwdlib import PasswordHash, exceptions
from pwdlib.hashers.argon2 import Argon2Hasher
from pwdlib.hashers.bcrypt import BcryptHasher

password_hash = PasswordHash((
    Argon2Hasher(),
    BcryptHasher(),
))
```

[`PasswordHash`](./reference/pwdlib.md#pwdlib.PasswordHash) expects a tuple (or list) of hashing algorithms.

!!! warning "The corresponding dependencies must be installed"

    Hashing algorithms are available through third-party implementations. Therefore, you should install the extra for all the algorithms you want to use.

    **For Argon2**

    ```sh
    pip install 'pwdlib[argon2]'
    ```

    **For Bcrypt**

    ```sh
    pip install 'pwdlib[bcrypt]'
    ```

    **Both!**

    ```sh
    pip install 'pwdlib[argon2,bcrypt]'
    ```

The **first** algorithm in the list is considered the **current algorithm**. New and updated hashes will use this algorithm.

!!! tip "I don't know what to choose!"

    If you start a new application, you can instantiate [`PasswordHash`](./reference/pwdlib.md#pwdlib.PasswordHash) using the [`recommended`](./reference/pwdlib.md#pwdlib.PasswordHash.recommended) class method. It'll use the Argon2 algorithm under the hood.

    ```py
    password_hash = PasswordHash.recommended()
    ```

### Hash a password

Once you have a [`PasswordHash`](./reference/pwdlib.md#pwdlib.PasswordHash) instance, you can [`hash`](./reference/pwdlib.md#pwdlib.PasswordHash.hash) a user's password:

```py
hash = password_hash.hash("herminetincture")
```

The resulting string is a hash generated from the **current algorithm**, which you can safely store in your database.

!!! question "Where is the salt?"

    If you know about password hashing algorithms, you probably know that *salting* the password is an important security feature. Back in the days, it was common to store the salt separately from the hash. Nowadays, most algorithms have a specific structure allowing them to store algorithm parameters and salt along with the hash in one string.

    For example, here is an Argon2 hash:

    ```
    $argon2id$v=19$m=65536,t=3,p=4$ugY9gvgMUycvF7hrnoi8oQ$uqcZOh96YysaG+s3A+RcZIccgaiQsynxfBlqUNxeRT4
    ```

### Verify a password

When you want to verify a password corresponds to a hash, use the [`verify`](./reference/pwdlib.md#pwdlib.PasswordHash.verify) method:

```py
valid = password_hash.verify("herminetincture", hash)
```

Under the hood, it'll check against all the enabled algorithms. It means that if older users still have a hash with a legacy algorithm, we'll still be able to verify it.

The resulting boolean indicates you if the hash corresponds to this password or not.

However, in most cases, you probably want to use the method we describe below.

### Verify and update a password

As we said, [`verify`](./reference/pwdlib.md#pwdlib.PasswordHash.verify) checks the hash against all the enabled algorithms. However, it's generally a good idea to take this chance to update the hash to the more secure current algorithm.

This is the purpose of the [`verify_and_update`](./reference/pwdlib.md#pwdlib.PasswordHash.verify_and_update) method: it verifies the password against a hash and, if it's valid and using an outdated algorithm, will hash it again using the current algorithm.


```py
valid, updated_hash = password_hash.verify_and_update("herminetincture", hash)
```

If the hash needs to be updated, `updated_hash` will be a string. Otherwise, it's `None`. Then, don't forget to update it in your database.

It's worth to note that the hash is also upgraded if the **settings of the algorithm** has been changed, like the time or memory cost.

## Password strength checking

`pwdlib` also includes password strength checking capabilities through [zxcvbn](https://github.com/dropbox/zxcvbn), a password strength estimator. This is a Rust-based implementation providing fast and accurate password strength measurement.

!!! warning "The zxcvbn extra must be installed"

    The zxcvbn functionality is built from Rust code and requires the `zxcvbn` extra to be installed:

    ```sh
    pip install 'pwdlib[zxcvbn]'
    ```

### Check password strength

You can check the strength of a password using the `zxcvbn` function:

```py
from pwdlib.zxcvbn import zxcvbn

result = zxcvbn("p@ssw0rd")
print(f"Score: {result.score}")  # Score from 0 (weak) to 4 (strong)
print(f"Guesses: {result.guesses}")  # Estimated guesses needed to crack
```

The result includes:

- `score`: A score from 0-4, where scores less than 3 are considered too weak
- `guesses`: Estimated number of guesses needed to crack the password
- `crack_times_seconds`: Crack time estimates for various scenarios
- `crack_times_display`: Human-readable crack time estimates
- `feedback`: Suggestions for improving the password (when score ≤ 2)

### Provide user context

You can also provide user-specific inputs to detect passwords that are weak in the context of that user:

```py
result = zxcvbn("john1990", user_inputs=["john", "doe", "1990"])
# This will detect that the password uses personal information
```
