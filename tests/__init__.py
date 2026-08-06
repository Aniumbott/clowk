"""Shared test helpers.

Kept to the minimum: only what more than one test module needs and cannot be written without
patching an interpreter default.
"""
import builtins
import contextlib
import re

_SGR = re.compile(r"\x1b\[[0-9;]*m")


def plain(text):
    """`text` with SGR escapes removed, for assertions about wording rather than styling.

    The block reason bolds the $NAMEs on hosts verified to render escapes, which splits any
    assertion that expects a name and the words after it to be adjacent. Tests that care about the
    escapes assert on them directly; every other test wants to read the sentence.
    """
    return _SGR.sub("", text)


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
