# pwdlib

<p align="center">
    <em>Modern password hashing for Python</em>
</p>

[![build](https://github.com/frankie567/pwdlib/workflows/Build/badge.svg)](https://github.com/frankie567/pwdlib/actions)
[![codecov](https://codecov.io/gh/frankie567/pwdlib/branch/main/graph/badge.svg)](https://codecov.io/gh/frankie567/pwdlib)
[![PyPI version](https://badge.fury.io/py/pwdlib.svg)](https://badge.fury.io/py/pwdlib)
[![Downloads](https://pepy.tech/badge/pwdlib)](https://pepy.tech/project/pwdlib)

<p align="center">
<a href="https://polar.sh/frankie567">
<picture>
  <source media="(prefers-color-scheme: dark)" srcset="https://polar.sh/embed/subscribe.svg?org=frankie567&darkmode=1">
  <img alt="Subscribe" src="https://polar.sh/embed/subscribe.svg?org=frankie567">
</picture>
</a>
</p>

---

**Documentation**: <a href="https://frankie567.github.io/pwdlib/" target="_blank">https://frankie567.github.io/pwdlib/</a>

**Source Code**: <a href="https://github.com/frankie567/pwdlib" target="_blank">https://github.com/frankie567/pwdlib</a>

---

## Quickstart

```sh
pip install 'pwdlib[argon2]'
```

```py
from pwdlib import PasswordHash

password_hash = PasswordHash.recommended()
hash = password_hash.hash("herminetincture")
password_hash.verify("herminetincture", hash)  # True
```

## Why `pwdlib`?

For years, the de-facto standard to hash passwords was [`passlib`](https://foss.heptapod.net/python-libs/passlib). Unfortunately, it has not been very active recently and its [maintenance status is under question](https://foss.heptapod.net/python-libs/passlib/-/issues/187). Starting Python 3.13, `passlib` won't work anymore.

That's why I decided to start `pwdlib`, a password hash helper for the modern Python era. However, it's **not designed to be a complete replacement** for `passlib`, which supports numerous [hashing algorithms and features](https://passlib.readthedocs.io/en/stable/lib/index.html).

**✅ Goals**

- [x] Provide an easy-to-use wrapper to hash and verify passwords
- [x] Support modern and secure algorithms like Argon2 or Bcrypt

**❌ Non-goals**

- [ ] Support legacy hashing algorithms like MD5
- [ ] Implement algorithms directly — we should only rely on existing and battle-tested implementations

## Development

### Setup environment

We use [Hatch](https://hatch.pypa.io/latest/install/) to manage the development environment and production build. Ensure it's installed on your system.

### Run unit tests

You can run all the tests with:

```bash
hatch run test
```

### Format the code

Execute the following command to apply linting and check typing:

```bash
hatch run lint
```

### Publish a new version

You can bump the version, create a commit and associated tag with one command:

```bash
hatch version patch
```

```bash
hatch version minor
```

```bash
hatch version major
```

Your default Git text editor will open so you can add information about the release.

When you push the tag on GitHub, the workflow will automatically publish it on PyPi and a GitHub release will be created as draft.

## Serve the documentation

You can serve the Mkdocs documentation with:

```bash
hatch run docs-serve
```

It'll automatically watch for changes in your code.

## License

This project is licensed under the terms of the MIT license.
