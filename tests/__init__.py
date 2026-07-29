"""Shared test helpers.

Kept to the minimum: only what more than one test module needs and cannot be written without
patching an interpreter default.
"""
import builtins
import contextlib


@contextlib.contextmanager
def default_encoding(name):
    """Make every text-mode open() that passes no encoding= use `name`.

    That is what CPython already does: `open()` with no encoding uses the locale codec, which on
    stock Windows is the ANSI codepage (cp1252, cp932, cp936) rather than UTF-8. There is no way
    to reproduce that on a UTF-8 POSIX box without patching the default, and PEP 686's UTF-8
    default lands well above clowk's 3.8 floor, so it is no escape hatch either.

    Binary opens are left alone, so shutil.copy2 and the tests' own byte-level reads still work.
    """
    real_open = builtins.open

    def fake_open(file, mode="r", buffering=-1, encoding=None, *args, **kwargs):
        if encoding is None and "b" not in mode:
            encoding = name
        return real_open(file, mode, buffering, encoding, *args, **kwargs)

    builtins.open = fake_open
    try:
        yield
    finally:
        builtins.open = real_open
