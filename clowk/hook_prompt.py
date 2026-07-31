#!/usr/bin/env python3
"""clowk pre-transmit prompt hook: detect a pasted credential -> file it -> block the turn.

This is the only part of clowk that prevents a leak. It runs locally, before the prompt is
transmitted, on Claude Code (UserPromptSubmit), Codex (UserPromptSubmit) and Gemini CLI
(BeforeAgent).

No host can rewrite a submitted prompt, so the flow is block-and-repaste, with the rewrite
placed on the clipboard.

EVERY HOST FAILS OPEN: if this script crashes or times out, the secret is transmitted. Hence
stdlib only, no network, and a bare except around the whole body.

Bypass: start the message with `unclowk` to send it raw.
"""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from clowk import clip, hosts, vault
from clowk.detect import scan

BYPASS = "unclowk"

# Appended to the rewritten prompt the user repastes, so it reaches the agent in the same message as
# the $NAME it explains. Addressed to the agent, not the human.
SKILL_POINTER = (
    "[assistant: $NAME above is a credential clowk holds. It is NOT in your environment and you must "
    "never print it. Use it as psql \"$(clowk get NAME)\". Read the clowk skill first.]")

# Most values one prompt will ever be filed under. A prompt with more hits than this is a pasted
# log, not a credential paste: 1800 lines of `request_id=<32 hex>` trips the shape-only rules ~170
# times, and vault.store reloads and rewrites the whole file per call, so filing them all costs
# O(hits x vault size) and leaves ~170 junk entries that come back one `clowk clear` at a time.
# Everything past the cap is still redacted and the turn is still blocked -- only filing stops.
MAX_FILED = 20

# Longest rewrite echoed into the block reason when the clipboard already has it. Without this a
# 200 KB log paste produced a 220 KB reason, which is what the host shows the user. Never applied
# when the clipboard copy failed: there the echo is the user's only copy of the rewrite.
ECHO_LIMIT = 4000


# Sessions that have already been shown the pointer. A session blocking five credentials does not
# need the explanation five times -- the agent read it the first time and the skill stays loaded.
def _seen_path():
    return os.environ.get("CLOWK_SESSIONS",
                          os.path.join(os.path.dirname(vault.path()), "sessions.json"))


# Enough to cover any plausible run of concurrent sessions without the file growing without bound.
MAX_SESSIONS = 64


def pointer_needed(session_id):
    """True the first time this session blocks something. Never raises.

    With no session id -- a host whose payload does not carry one -- this returns True every time.
    Repeating the pointer costs tokens; omitting it costs the agent the one thing that stops it
    printing a credential, so the failure is deliberately biased towards repeating.
    """
    if not session_id:
        return True
    path = _seen_path()
    try:
        with open(path, encoding="utf-8") as f:
            seen = json.load(f)
        if not isinstance(seen, list):
            seen = []
    except Exception:  # noqa: BLE001 -- missing, corrupt, unreadable: treat as "not seen"
        seen = []
    if session_id in seen:
        return False
    seen.append(session_id)
    del seen[:-MAX_SESSIONS]          # oldest first, so this keeps the most recent
    try:
        parent = os.path.dirname(path)
        if parent and not os.path.isdir(parent):
            os.makedirs(parent)
        tmp = path + ".tmp"
        with open(tmp, "w", encoding="utf-8", newline="") as f:
            json.dump(seen, f)
        os.replace(tmp, path)
    except Exception:  # noqa: BLE001 -- cannot record it, so it will be sent again. Harmless.
        pass
    return True


def _host_from(argv):
    for i, arg in enumerate(argv):
        if arg == "--host" and i + 1 < len(argv):
            return argv[i + 1]
        if arg.startswith("--host="):
            return arg.split("=", 1)[1]
    return "claude-code"


def build_message(rewritten, stored, tiers, copied, unfiled=(), skipped=0):
    """The block reason. Plain text: hooks cannot set colour or markdown."""
    lines = ["clowk stopped a credential before it reached the model."]
    for name in stored:
        tier = tiers.get(name, "")
        note = "  (shape-only match -- if this is a false positive, run: clowk clear %s)" % name if tier == "low" else ""
        lines.append("  stored as $%s%s" % (name, note))
    for name in unfiled:
        lines.append("  NOT filed as $%s -- clowk could not write %s, so keep this value "
                     "yourself (check permissions and free space)" % (name, vault.path()))
    if skipped:
        lines.append("  and %d more redacted but NOT filed -- %d hits in one message reads as a "
                     "pasted log rather than a credential paste, and filing them all would bury "
                     "the vault in junk. If none of them are credentials, resend with %s."
                     % (skipped, skipped + len(stored) + len(unfiled), BYPASS))
    lines.append("")
    lines.append("Your prompt, rewritten%s:" % (" -- already on your clipboard" if copied else ""))
    lines.append("")
    if copied and len(rewritten) > ECHO_LIMIT:
        lines.append("    [%d characters, not repeated here -- paste it from the clipboard]"
                     % len(rewritten))
    else:
        lines.append("    " + rewritten)
    lines.append("")
    lines.append("To send the original text instead, start your message with:  %s" % BYPASS)
    return "\n".join(lines)


def read_payload(stdin):
    """Return the raw payload text, decoded as UTF-8 whatever the locale codec is.

    Hosts send UTF-8 JSON, but sys.stdin decodes with the locale codec, so on a non-UTF-8 locale
    (every Windows default ANSI codepage: cp1252, cp932, cp936) one non-ASCII byte raised
    UnicodeDecodeError -- and that subclasses ValueError, so it was indistinguishable from
    malformed JSON: exit 0, no block, credential transmitted. Claude Code puts `cwd` in every
    payload, so an accented character in a profile path disabled the hook for every prompt.

    `errors="replace"` cannot raise, and U+FFFD cannot hide a credential: every rule's value
    half is ASCII. Non-UTF-8 stdio also mojibaked the rewrite the user is told to repaste.
    """
    raw = getattr(stdin, "buffer", None)  # absent on the StringIO the tests pass in
    if raw is None:
        return stdin.read()
    return raw.read().decode("utf-8", "replace")


def main(argv, stdin, stdout, stderr):
    host = _host_from(argv)
    try:
        text = read_payload(stdin)
    except UnicodeDecodeError as e:
        # A scan that did not happen is not a clean prompt. Never block on a payload we cannot
        # read -- it may not even be ours -- but do not look healthy either.
        stderr.write("clowk: cannot decode this payload as %s -- NOT scanning it\n" % e.encoding)
        return 0
    try:
        payload = json.loads(text)
    except ValueError:
        return 0  # unparseable input: never block on our own confusion

    event = hosts.read_event(payload)
    prompt = event["prompt"]
    if not prompt or prompt.lstrip().lower().startswith(BYPASS):
        return 0

    findings = scan(prompt)
    if not findings:
        return 0  # nothing detected -> pass through untouched

    # From here on the turn IS blocked. Everything below is presentation and bookkeeping, and
    # none of it may cancel the block: filing is best-effort, blocking is not. Emitting a
    # generic reason is always better than letting an exception reach the fail-open handler,
    # which would transmit the credential with nothing on either stream.
    try:
        reason = capture(event, findings)
    except Exception:  # noqa: BLE001 -- see above; deliberately never re-raised
        # No rewrite here: a half-substituted prompt could still hold a raw value.
        reason = ("clowk found a credential in this message but hit an internal error, so it was "
                  "neither filed nor rewritten.\n\nTo send the original text anyway, start your "
                  "message with:  %s" % BYPASS)
    return hosts.block(host, reason, stdout, stderr)


def capture(event, findings):
    """Redact every finding out of the prompt, file what it can, return the block reason.

    Redaction is unconditional; filing is not -- it stops at MAX_FILED and tolerates a vault
    that cannot be written. Raising here only costs the reason text, never the block.
    """
    rewritten, stored, unfiled, tiers = event["prompt"], [], [], {}
    taken, skipped = set(), 0
    # Longest secret first, and skip anything a longer match already swallowed. Rules do nest:
    # flutterwave-encryption-key's pattern is a prefix of flutterwave-secret-key's, so one
    # pasted key yields two findings. Replacing the short one first would leave the tail of the
    # real value in the rewrite -- which is what goes on the clipboard and gets repasted.
    for finding in sorted(findings, key=lambda f: len(f.secret), reverse=True):
        if finding.secret not in rewritten:
            continue
        if len(stored) >= MAX_FILED:
            name = _placeholder(finding.env, taken)  # redacted, deliberately not filed
            skipped += 1
        else:
            try:
                name = vault.store(
                    finding.env, finding.secret,
                    rule=finding.rule_id, confidence=finding.confidence, source=event["cwd"],
                )
            except Exception:  # noqa: BLE001 -- unwritable/full/hand-edited vault; note, not raise
                name = _placeholder(finding.env, taken)
                unfiled.append(name)
            else:
                stored.append(name)
        taken.add(name)
        # Outside the try on purpose: a value clowk did not file must still leave the prompt,
        # or the raw secret would land in the reason and on the clipboard.
        rewritten = rewritten.replace(finding.secret, "$" + name)
        tiers[name] = finding.confidence

    # The pointer has to be INSIDE the text the user repastes, not merely in the block reason.
    # A blocked turn transmits nothing, so the reason is read by the human and never reaches the
    # model -- putting the pointer only there made it decorative: the agent received a bare $NAME
    # with no idea what it meant, which is precisely what it was added to prevent. The repasted
    # prompt is the only channel from a blocked turn to the model.
    if (stored or unfiled) and pointer_needed(event.get("session_id", "")):
        rewritten = rewritten + "\n\n" + SKILL_POINTER
    copied = clip.copy(rewritten)
    return build_message(rewritten, stored, tiers, copied, unfiled, skipped)


def _placeholder(env, taken):
    """The $NAME to substitute for a value clowk did not file. `taken` is a set of used names.

    Suffixed the way vault.store suffixes a clash, so two different values never collapse into
    one placeholder -- that would assert two secrets are the same secret.
    """
    name, n = env, 2
    while name in taken:
        name = "%s_%d" % (env, n)
        n += 1
    return name


if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv[1:], sys.stdin, sys.stdout, sys.stderr))
    except Exception:  # noqa: BLE001 -- every host fails open; never let a traceback block a turn
        sys.exit(0)
