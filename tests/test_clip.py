"""Tests for the best-effort clipboard.

No test here may spawn a real clipboard tool. A genuine pbcopy/xclip overwrites the developer's
clipboard by definition, so "check it works on this platform" and "leave the machine alone" are
mutually exclusive -- and a suite that silently destroys whatever you had copied is not worth a
tautological assertion. Every test points clip.CANDIDATES at a stub instead, and the stub writes
what it was handed to a temp file so the delivered bytes can be asserted exactly.
"""
import os
import shutil
import sys
import tempfile
import unittest

from clowk import clip

# A clipboard tool that is not a clipboard: it copies stdin to the file named in argv[1].
_SINK = "import sys; open(sys.argv[1], 'wb').write(sys.stdin.buffer.read())"
# Reads its input, then fails -- so copy() must not report success and must try the next entry.
_REFUSER = "import sys; sys.stdin.buffer.read(); sys.exit(3)"


class ClipCase(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="clowk-clip-")
        self.addCleanup(shutil.rmtree, self.dir, True)
        # mkdtemp + join rather than NamedTemporaryFile: on Windows a child process cannot open
        # a temp file the parent still holds.
        self.sink = os.path.join(self.dir, "sink")
        self.addCleanup(setattr, clip, "CANDIDATES", clip.CANDIDATES)
        self.addCleanup(setattr, clip, "COPY_TIMEOUT", clip.COPY_TIMEOUT)

    def sink_tool(self):
        return [sys.executable, "-c", _SINK, self.sink]

    def delivered(self):
        with open(self.sink, "rb") as f:
            return f.read()


class TestCopy(ClipCase):
    def test_returns_false_and_does_not_raise_when_no_tool_exists(self):
        clip.CANDIDATES = [["clowk-nonexistent-clipboard-binary"]]
        self.assertFalse(clip.copy("hello"))

    def test_the_clipboard_tool_receives_the_exact_utf8_bytes(self):
        # Non-ASCII and multi-line on purpose: the encode is a contract, not an implementation
        # detail, and a rewritten prompt can contain either.
        text = "line one: éèê\nline two: 中文 \U0001f511\n"
        clip.CANDIDATES = [self.sink_tool()]
        self.assertTrue(clip.copy(text))
        self.assertEqual(self.delivered(), text.encode("utf-8"))

    def test_a_tool_that_exits_nonzero_is_not_reported_as_a_copy(self):
        clip.CANDIDATES = [[sys.executable, "-c", _REFUSER]]
        self.assertFalse(clip.copy("hello"))

    def test_a_candidate_that_fails_is_skipped_for_the_next_one(self):
        clip.CANDIDATES = [
            ["clowk-nonexistent-clipboard-binary"],  # never spawns at all
            [sys.executable, "-c", _REFUSER],        # spawns, then exits nonzero
            self.sink_tool(),                        # the one that actually works
        ]
        self.assertTrue(clip.copy("fallthrough"))
        self.assertEqual(self.delivered(), b"fallthrough")

    def test_empty_text_is_false_without_spawning_anything(self):
        clip.CANDIDATES = [self.sink_tool()]
        self.assertFalse(clip.copy(""))
        # The stub writes its file unconditionally, so its absence proves nothing was spawned.
        self.assertFalse(os.path.exists(self.sink))

    def test_a_hanging_tool_times_out_instead_of_wedging_the_hook(self):
        clip.CANDIDATES = [[sys.executable, "-c", "import time; time.sleep(30)"]]
        clip.COPY_TIMEOUT = 0.2
        self.assertFalse(clip.copy("hello"))


class TestCandidates(unittest.TestCase):
    """The shipped argv list, checked without spawning any of it."""

    def test_every_shipped_candidate_is_a_non_empty_argv_of_non_empty_strings(self):
        self.assertTrue(clip.CANDIDATES)
        for argv in clip.CANDIDATES:
            self.assertIsInstance(argv, list, argv)
            self.assertTrue(argv, argv)
            for word in argv:
                self.assertIsInstance(word, str, argv)
                self.assertTrue(word, argv)


if __name__ == "__main__":
    unittest.main()
