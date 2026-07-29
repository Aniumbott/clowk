"""Put the rewritten prompt on the clipboard so repaste is one keystroke.

Best-effort by design: no host can rewrite a submitted prompt, so block-and-repaste is the
universal UX, and this is what makes it cheap. If no clipboard tool exists we return False and
the caller still prints the text.

ponytail: subprocess is fine here -- clip.py is NOT imported by the prompt hook's hot path
until after a secret has already been found and the turn is being blocked.

Two things this module must never do, because it runs inside a hook that fails open:
  - hang. Every spawn is bounded by COPY_TIMEOUT; a wedged clipboard tool would otherwise
    time the whole hook out, and a timed-out hook transmits the secret.
  - write to the hook's stdout or stderr. Those are the block protocol, so a chatty
    clipboard tool would corrupt the decision. Child output goes to DEVNULL.
"""
import subprocess

# Seconds to wait for one clipboard tool before giving up on it and trying the next.
COPY_TIMEOUT = 2.0

CANDIDATES = [
    ["pbcopy"],                       # macOS
    ["wl-copy"],                      # Wayland
    ["xclip", "-selection", "clipboard"],  # X11
    ["xsel", "--clipboard", "--input"],    # X11 alternative
    ["clip.exe"],                     # Windows / WSL
]


def copy(text):
    """Return True if text reached a clipboard. Never raises."""
    if not text:
        return False
    for argv in CANDIDATES:
        try:
            proc = subprocess.Popen(
                argv,
                stdin=subprocess.PIPE,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            proc.communicate(text.encode("utf-8"), timeout=COPY_TIMEOUT)
            if proc.returncode == 0:
                return True
        except subprocess.TimeoutExpired:
            _abandon(proc)
        except (OSError, ValueError):
            continue
    return False


def _abandon(proc):
    """Kill a clipboard tool that stopped responding, and reap it. Never raises."""
    try:
        proc.kill()
        proc.communicate()
    except (OSError, subprocess.SubprocessError):
        pass
