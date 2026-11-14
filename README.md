# pwdlib
<!-- ALL-CONTRIBUTORS-BADGE:START - Do not remove or modify this section -->
[![All Contributors](https://img.shields.io/badge/all_contributors-1-orange.svg?style=flat-square)](#contributors-)
<!-- ALL-CONTRIBUTORS-BADGE:END -->

<p align="center">
    <em>Modern password hashing for Python</em>
</p>

[![build](https://github.com/frankie567/pwdlib/workflows/Build/badge.svg)](https://github.com/frankie567/pwdlib/actions)
[![codecov](https://codecov.io/gh/frankie567/pwdlib/branch/main/graph/badge.svg)](https://codecov.io/gh/frankie567/pwdlib)
[![PyPI version](https://badge.fury.io/py/pwdlib.svg)](https://badge.fury.io/py/pwdlib)
[![Downloads](https://pepy.tech/badge/pwdlib)](https://pepy.tech/project/pwdlib)

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

Install [uv](https://docs.astral.sh/uv/) and [just](https://just.systems/). Use Python 3.11 or newer for Zensical and pre-commit.

Install the development dependencies and pre-commit hooks with `just install`.

### Run unit tests

```bash
just test
```

### Format the code

Run Ruff to format and lint the code, then check types with ty.

```bash
just lint
```

Use `just lint-check` to run the same checks without editing files.

### Publishing a release

1. Commit the release notes under `Unreleased` in [CHANGELOG.md](CHANGELOG.md).
   From a clean release branch with Git signing configured, run `just version patch`,
   `just version minor`, or `just version major`. The recipe updates the version,
   changelog, and lockfile, then opens your Git editor for the signed commit.
2. Preview the release notes with `just release-notes <version>`, then push the
   branch and merge the release PR into `main`.
3. With the GitHub CLI authenticated, run `just release <PR number>`. This signs
   and pushes a tag pointing to the merged PR commit. After the checks pass,
   CI publishes the distributions to PyPI with attestations and publishes the
   GitHub release with build provenance.

The PyPI Trusted Publisher must match the `build.yml` workflow and the GitHub
`release` environment.

## Serve the documentation

The documentation uses Zensical. Start the local preview with the following command.

```bash
just docs-serve
```

Open http://localhost:8000. The preview reloads when documentation changes.
Edit pages in `docs/` and configure the site in `zensical.toml`.

Build the static site into `site/` with the following command.

```bash
just docs-build
```

## License

This project is licensed under the terms of the MIT license.

## Contributors ✨

Thanks goes to these wonderful people ([emoji key](https://allcontributors.org/docs/en/emoji-key)):

<!-- ALL-CONTRIBUTORS-LIST:START - Do not remove or modify this section -->
<!-- prettier-ignore-start -->
<!-- markdownlint-disable -->
<table>
  <tbody>
    <tr>
      <td align="center" valign="top" width="14.28%"><a href="https://hynek.me/about/"><img src="https://avatars.githubusercontent.com/u/41240?v=4?s=100" width="100px;" alt="Hynek Schlawack"/><br /><sub><b>Hynek Schlawack</b></sub></a><br /><a href="https://github.com/frankie567/pwdlib/commits?author=hynek" title="Code">💻</a></td>
      <td align="center" valign="top" width="14.28%"><a href="https://github.com/waketzheng"><img src="https://avatars.githubusercontent.com/u/35413830?v=4?s=100" width="100px;" alt="Waket Zheng"/><br /><sub><b>Waket Zheng</b></sub></a><br /><a href="https://github.com/frankie567/pwdlib/commits?author=waketzheng" title="Code">💻</a></td>
    </tr>
  </tbody>
</table>

<!-- markdownlint-restore -->
<!-- prettier-ignore-end -->

<!-- ALL-CONTRIBUTORS-LIST:END -->

This project follows the [all-contributors](https://github.com/all-contributors/all-contributors) specification. Contributions of any kind welcome!
