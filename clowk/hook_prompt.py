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
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from clowk import clip, hosts, vault
from clowk.detect import scan

BYPASS = "unclowk"

# Appended to the rewritten prompt the user repastes, so it reaches the agent in the same message as
# the $NAME it explains. Addressed to the agent, not the human.
SKILL_POINTER = (
    "[assistant: $NAME is a credential clowk holds. Never print it. "
    "Use $(clowk get NAME) — see the clowk skill.]")

# Most values one prompt will ever be filed under. A prompt with more hits than this is a pasted
# log, not a credential paste: 1800 lines of `request_id=<32 hex>` trips the shape-only rules ~170
# times, and vault.store reloads and rewrites the whole file per call, so filing them all costs
# O(hits x vault size) and leaves ~170 junk entries that come back one `clowk clear` at a time.
# Everything past the cap is still redacted and the turn is still blocked -- only filing stops.
MAX_FILED = 20

# Longest rewrite echoed WHOLE into the block reason when the clipboard already has it. Without a
# cap a 200 KB log paste produced a 220 KB reason, which is what the host shows the user.
#
# Above the cap the echo used to be replaced entirely by a character count, which overshot: the
# user was told to paste something they could see no part of. Now it keeps the head and the tail,
# which is what answers the only question the echo is there for -- is this the message I meant? --
# and the head is the larger share because that is where a person's own instruction sits.
#
# 1000 characters is a dozen lines, so anything a person actually typed around a credential is
# still shown in full. Never applied when the clipboard copy failed: there the echo is the user's
# only copy of the rewrite, so it is printed whole however long it is.
#
# The limit is deliberately larger than head + tail, so an elision always hides at least 200
# characters. Equal to it, a 1001-character rewrite would print "1 more characters" and two thirds
# of a marker's worth of nothing.
ECHO_LIMIT = 1000
ECHO_HEAD = 500
ECHO_TAIL = 300


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


def build_message(rewritten, stored, tiers, copied, unfiled=(), skipped=0, rotated=None):
    """The block reason. Plain text -- hooks cannot set colour or markdown -- but emoji carry fine.

    Kept short on purpose. This is read by a person who has just been interrupted mid-thought, so it
    answers three questions in order and stops: what happened, what do I paste, how do I override.
    The reasoning behind each rule belongs in the README, not here.

    `rotated` maps a filed name to the name that already holds a different value of the same kind.
    That line is the only warning the user gets that their habitual $NAME still resolves to the
    revoked key, and this is the one moment they can act on it, so it names the remedy too.
    """
    rotated = rotated or {}
    lines = ["👀 clowk caught a credential before it reached the model.", ""]
    for name in stored:
        hint = "   ·  shape-only guess, `clowk clear %s` if wrong" % name \
            if tiers.get(name) == "low" else ""
        lines.append("   💾  $%s%s" % (name, hint))
        stale = rotated.get(name)
        if stale:
            lines.append("       ↻  $%s already holds a different value of the same kind."
                         % stale)
            lines.append("          Rotated it upstream?")
            lines.append("          `clowk set %s` makes this the value that name resolves to."
                         % stale)
    for name in unfiled:
        lines.append("   ⚠️   $%s not saved — could not write %s, so keep this one yourself"
                     % (name, vault.path()))
    if skipped:
        lines.append("   ⚠️   %d more hidden but not saved — %d hits in one message looks like a "
                     "pasted log" % (skipped, skipped + len(stored) + len(unfiled)))
    lines.append("")
    lines.append("📋 Paste this%s:" % (" — already on your clipboard" if copied else ""))
    lines.append("")
    if copied and len(rewritten) > ECHO_LIMIT:
        head, tail = _elide(rewritten)
        _echo(lines, head)
        lines.append("   ⋯  %d more characters — the whole message is on your clipboard"
                     % (len(rewritten) - len(head) - len(tail)))
        _echo(lines, tail)
    else:
        _echo(lines, rewritten)
    lines.append("")
    lines.append("🤔 Not a credential? Resend starting with  %s" % BYPASS)
    return "\n".join(lines)


def _echo(lines, text):
    """Append `text` to the message, indented under the paste heading."""
    for line in text.split("\n"):
        lines.append("   " + line if line else "")


def _elide(text):
    """(head, tail) of `text`, cut at a line boundary when one is near enough to the limit.

    Cutting mid-word reads like corruption rather than like an omission, and the marker between
    the two halves has to be believed -- so the boundary is preferred whenever there is one in the
    second half of the head or the first half of the tail. A single enormous line has neither, and
    then the hard cut stands.
    """
    head = text[:ECHO_HEAD]
    cut = head.rfind("\n")
    if cut > ECHO_HEAD // 2:
        head = head[:cut]
    tail = text[-ECHO_TAIL:]
    cut = tail.find("\n")
    if -1 < cut < ECHO_TAIL // 2:
        tail = tail[cut + 1:]
    return head, tail


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
    prompt = event["prompt"]
    stored, unfiled, tiers, rotated = [], [], {}, {}
    taken, names, skipped, resume = set(), {}, 0, {}
    pattern = _one_pass(f.secret for f in findings)
    by_secret = dict((f.secret, f) for f in findings)
    # Only the values that survived the match -- see _matched. What a longer overlapping finding
    # swallowed never reaches this loop, so it is never filed either, which is what the old
    # "is it still in the partially rewritten prompt?" test was reaching for.
    #
    # Still longest first, even though substitution no longer needs an order. It decides WHICH 20
    # values MAX_FILED files, and length is a rough proxy for "a real key rather than log noise":
    # in text order, a genuine 48-character `sk_live_...` pasted below thirty 32-hex log lines
    # falls outside the cap and is never written to the vault at all, so `clowk get` cannot reach
    # it once the terminal has scrolled. Redaction is unaffected either way.
    for secret in sorted(_matched(pattern, prompt), key=len, reverse=True):
        finding = by_secret[secret]
        if len(stored) >= MAX_FILED:
            name = _placeholder(finding.env, taken, resume)  # redacted, not filed
            skipped += 1
        else:
            try:
                name, stale = vault.store(
                    finding.env, finding.secret,
                    rule=finding.rule_id, confidence=finding.confidence, source=event["cwd"],
                    detail=True,
                )
            except Exception:  # noqa: BLE001 -- unwritable/full/hand-edited vault; note, not raise
                name = _placeholder(finding.env, taken, resume)
                unfiled.append(name)
            else:
                stored.append(name)
                if stale:
                    rotated[name] = stale
        taken.add(name)
        # Outside the try on purpose: a value clowk did not file must still leave the prompt,
        # or the raw secret would land in the reason and on the clipboard.
        names[secret] = name
        tiers[name] = finding.confidence
    rewritten = pattern.sub(lambda m: "$" + names[m.group(0)], prompt) if names else prompt

    # The pointer has to be INSIDE the text the user repastes, not merely in the block reason.
    # A blocked turn transmits nothing, so the reason is read by the human and never reaches the
    # model -- putting the pointer only there made it decorative: the agent received a bare $NAME
    # with no idea what it meant, which is precisely what it was added to prevent. The repasted
    # prompt is the only channel from a blocked turn to the model.
    if (stored or unfiled) and pointer_needed(event.get("session_id", "")):
        rewritten = rewritten + "\n\n" + SKILL_POINTER
    copied = clip.copy(rewritten)
    return build_message(rewritten, stored, tiers, copied, unfiled, skipped, rotated)


# --- one-pass redaction -------------------------------------------------------------------------
# Every found value has to leave the prompt, all of its occurrences, with the longest overlapping
# finding winning. That used to be one `str.replace` over the whole prompt per finding, i.e.
# O(findings x prompt length) -- and on credential-dense text findings grow WITH length, so the
# real curve was quadratic. Measured on `2026-08-05 INFO api_key=<32 hex> request served` lines:
# 70 KB/1000 findings 0.13s, 141 KB 0.45s, 281 KB 1.62s, 563 KB 6.32s, while scan() stayed flat
# at 2.0x per doubling. Extrapolated, ~1.7 MB of that text passes Claude Code's 60s hook timeout,
# and a timed-out hook transmits the whole paste. So this is a fail-open bug, not a slow path.
#
# One compiled alternation of the found values, longest first, was the obvious fix and is NOT one:
# `re` walks a BRANCH alternative by alternative at every start position, so it is quadratic in
# exactly the same way. Measured, same fixture: 563 KB/8000 alternatives 6.77s and 1.3 MB/18000
# 34.92s -- worse than the str.replace loop it replaced.
#
# So the alternation is built as a TRIE, which is a shared-prefix regex: 16 first-character
# branches to reject instead of 18000 whole alternatives. Same fixture, build + compile + sub:
# 563 KB 0.22s, 1.3 MB 0.50s, 2.9 MB/40000 findings 1.18s. Linear, and 30x under the timeout at a
# size the old code could not finish.
#
# What one leftmost scan gives up against a global longest-first loop is STRADDLING overlap: two
# findings that overlap where neither contains the other. There the scan commits to whichever
# starts first and never revisits the other's start, so bytes of the loser can survive. It is
# reachable -- `DATABASE_URL=postgresql://svc:PASS@db/o;Password=PASS;` makes clowk's URI rule and
# its key=value rule straddle -- so it was measured rather than assumed, over 126 straddling texts
# the shipped ruleset produces: a WHOLE value survived 0 of 126 under both algorithms, and the
# longest surviving fragment was worse than the old loop's on 12, better on 9 and identical on
# 105. So this is a property of replacing non-overlapping spans, which both do, not a cost of the
# rewrite. Never leaving a whole value IS guaranteed, and by construction rather than by luck: an
# unmatched value's every occurrence must begin inside a committed match, or the scan would have
# matched it there, so its first byte is always replaced. A test pins that.
_END = ""   # marks "a secret ends at this node". Not a character, so it cannot collide with one.

# `re` parses nested groups recursively, so the trie stops nesting and flattens what is left.
# Measured, uncapped: 400 levels compile and 500 raise RecursionError, identically on 3.9, 3.11
# and 3.14 -- the boundary is the default 1000-frame limit, not anything version-specific.
# Realistic input is nowhere near: 8000 random 32-hex values branch 6 deep. 600 values that each
# branch off the previous one character later do blow it, and a RecursionError there costs the
# user the rewrite and the vault entry -- the block survives it, but nothing else does.
MAX_DEPTH = 40


def _one_pass(secrets):
    """One compiled pattern matching every secret, preferring the longest at each position."""
    root = {}
    for secret in secrets:
        if not secret:
            continue          # an empty alternative matches everywhere; nothing may produce one
        node = root
        for ch in secret:
            node = node.setdefault(ch, {})
        node[_END] = True
    return re.compile(_trie_pattern(root)) if root else None


def _trie_pattern(node, depth=0):
    """Regex source for one trie node, longest match first.

    A run of single-child nodes collapses into one literal, so a 400-character connection string
    costs one level of nesting rather than 400. Where a secret both ends at a node and continues
    past it -- flutterwave-encryption-key's value is a prefix of flutterwave-secret-key's -- the
    continuation is a GREEDY optional group, so the longer value is tried first and the shorter
    one still matches wherever the longer cannot complete.
    """
    run = []
    while len(node) == 1 and _END not in node:
        (ch, node), = node.items()
        run.append(ch)
    prefix = re.escape("".join(run))
    branches = sorted(ch for ch in node if ch != _END)
    if not branches:
        return prefix
    if depth >= MAX_DEPTH:
        return prefix + _flat(node)
    alts = [re.escape(ch) + _trie_pattern(node[ch], depth + 1) for ch in branches]
    if _END in node:
        return prefix + "(?:%s)?" % "|".join(alts)
    if len(alts) == 1:
        return prefix + alts[0]
    return prefix + "(?:%s)" % "|".join(alts)


def _flat(node):
    """The depth cap's fallback: everything below `node` as one flat alternation, longest first.

    Quadratic for this subtree alone, which is the trade -- only a pathological chain of nested
    prefixes gets here, and correctness is identical because longest-first is the ordering the
    `str.replace` loop used for every finding.
    """
    tails, stack = [], [("", node)]
    while stack:
        so_far, node = stack.pop()
        for ch, child in node.items():
            if ch == _END:
                tails.append(so_far)
            else:
                stack.append((so_far + ch, child))
    alts = [re.escape(t) for t in sorted((t for t in tails if t), key=len, reverse=True)]
    return "(?:%s)%s" % ("|".join(alts), "?" if "" in tails else "")


def _matched(pattern, text):
    """Distinct secrets `pattern` actually matches, in the order they first appear.

    Deliberately a separate pass from the substitution: a name can only be chosen once the match
    is known, and a value swallowed whole by a longer overlapping match must not be named at all.
    """
    out, seen = [], set()
    if pattern is None:
        return out
    for m in pattern.finditer(text):
        secret = m.group(0)
        if secret not in seen:
            seen.add(secret)
            out.append(secret)
    return out


def _placeholder(env, taken, resume):
    """The $NAME to substitute for a value clowk did not file. `taken` is a set of used names.

    Suffixed the way vault.store suffixes a clash, so two different values never collapse into
    one placeholder -- that would assert two secrets are the same secret.

    `resume` carries where each env got to, and is the other half of the one-pass fix above.
    Restarting the search at 2 every time made this O(placeholders^2), and the cap means a pasted
    log produces thousands of them: 7980 placeholders spent 4.4 of 5.3 seconds here, inside the
    same hook whose timeout transmits the prompt. Nothing else in the loop is worse than O(1).
    """
    name, n = env, resume.get(env, 2)
    while name in taken:
        name = "%s_%d" % (env, n)
        n += 1
    resume[env] = n
    return name


if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv[1:], sys.stdin, sys.stdout, sys.stderr))
    except Exception:  # noqa: BLE001 -- every host fails open; never let a traceback block a turn
        sys.exit(0)
