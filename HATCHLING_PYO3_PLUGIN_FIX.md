# Hatchling PyO3 Plugin Issue and Fix

## Issue

The hatchling-pyo3-plugin version 0.1.0 has a bug in the `_add_rust_artifacts` method at line 136 in `hooks.py`.

### Bug Description

The code uses:
```python
lib_patterns = ["*.so"]  # or ["*.dylib"], ["*.dll", "*.pyd"]
for pattern in lib_patterns:
    for lib_file in target_dir.glob(f"lib*{pattern}"):
```

This creates invalid glob patterns like `lib**.so` (double asterisk), which causes Python's pathlib to raise:
```
ValueError: Invalid pattern: '**' can only be an entire path component
```

### Fix

Change `lib_patterns` to `lib_suffix` and remove the `*` from the values:

```python
lib_suffix = [".so"]  # or [".dylib"], [".dll", ".pyd"]
for suffix in lib_suffix:
    for lib_file in target_dir.glob(f"lib*{suffix}"):
```

Apply the same change to both glob calls in the method (lines 136 and 142).

## Workaround for Development

Until the fix is published:

1. After running `cargo build --release`, manually copy the built library:
   ```bash
   cp target/release/lib_zxcvbn.so pwdlib/_zxcvbn.so
   ```

2. Or install a patched version of the plugin (when available):
   ```bash
   pip install git+https://github.com/frankie567/hatchling-pyo3-plugin@fix-glob-bug
   ```

## Status

- **Issue Identified**: November 3, 2025
- **Fix Submitted**: Pending
- **Plugin Version with Bug**: 0.1.0
