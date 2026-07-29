import sys
import unittest

from clowk import clip


class TestCopy(unittest.TestCase):
    def test_returns_false_and_does_not_raise_when_no_tool_exists(self):
        original = clip.CANDIDATES
        try:
            clip.CANDIDATES = [["clowk-nonexistent-clipboard-binary"]]
            self.assertFalse(clip.copy("hello"))
        finally:
            clip.CANDIDATES = original

    def test_returns_a_bool_on_the_real_platform(self):
        self.assertIn(clip.copy("clowk clipboard self-test"), (True, False))

    def test_empty_text_is_false_without_spawning_anything(self):
        self.assertFalse(clip.copy(""))

    def test_a_hanging_tool_times_out_instead_of_wedging_the_hook(self):
        candidates, timeout = clip.CANDIDATES, clip.COPY_TIMEOUT
        try:
            clip.CANDIDATES = [[sys.executable, "-c", "import time; time.sleep(30)"]]
            clip.COPY_TIMEOUT = 0.2
            self.assertFalse(clip.copy("hello"))
        finally:
            clip.CANDIDATES, clip.COPY_TIMEOUT = candidates, timeout


if __name__ == "__main__":
    unittest.main()
