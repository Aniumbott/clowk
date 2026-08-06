"""Secret detection using the vendored gitleaks ruleset (rules.json).
Keyword-gated + entropy-filtered, matching gitleaks semantics to keep false positives low.

Confidence tiers: a rule whose captured value OPENS with a fixed literal run -- ghp_, xoxb-,
AKIA, -----BEGIN -- is "high"; a shape-only rule is "low". Both still block -- blocking is
the only thing that prevents transmission -- but the tier changes the wording and lets
false-positive junk be purged from the vault later.

The test is deliberately narrow and it still errs low, but it no longer errs low on a pinned
prefix that happens to carry no trailing separator: `AKIA` used to read "low", so a live AWS key
came back annotated "shape-only guess, `clowk clear AWS_ACCESS_KEY_ID` if wrong". It only ever
looks at the part of a rule that produces the credential, never at the keyword context around it
-- see classify(). Never word a "low" message as "this is probably not a credential" -- word it
as "clowk is less sure what this is".
"""
import base64
import binascii
import json
import math
import os
import re
import sys
from collections import namedtuple

RULES_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "rules.json")


def load_rules(path):
    """Read the ruleset. Returns (rules, error) and never raises.

    This runs at import, i.e. while `from clowk.detect import scan` executes -- which is BEFORE
    hook_prompt's bare except exists. A traceback here is a non-zero exit from the prompt hook,
    every host reads that as a non-blocking hook error, and the prompt carrying the credential is
    transmitted. So a missing, truncated, unreadable or wrongly-shaped rules.json must degrade to
    "no rules" rather than crash. Degrading means clowk protects nothing, so say so out loud
    instead of looking healthy -- see RULESET_ERROR below.
    """
    try:
        with open(path, encoding="utf-8") as f:
            rules = json.load(f)
    except Exception as e:  # noqa: BLE001 -- missing/corrupt/unreadable; the type is the diagnosis
        return [], "cannot read %s (%s)" % (path, type(e).__name__)
    if not isinstance(rules, list) or not rules:
        return [], "%s is not a non-empty list of rules" % path
    return rules, ""


RULES, RULESET_ERROR = load_rules(RULES_PATH)

Finding = namedtuple("Finding", "rule_id env secret start end confidence")

# regex metacharacters: a group body free of all of them can only match one fixed string.
_META = frozenset("\\|.*+?[](){}^$")
# The assignment operator in gitleaks' keyword=value template. Present verbatim in 101 of the 221
# vendored rules, which is the measurement the standalone-token rule exists because of -- see
# STANDALONE_ID below. It no longer takes any part in classify(): reading the secret group's own
# content excludes the keyword context by construction, and does so whichever side of the value
# the keyword sits on.
_OPERATOR = r"(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)"


def _skip_class(rx, i):
    """i points at the '[' of a character class; return the index just past its ']'."""
    n = len(rx)
    i += 1
    if rx[i:i + 1] == "^":
        i += 1
    if rx[i:i + 1] == "]":  # a literal ] may lead the class
        i += 1
    while i < n and rx[i] != "]":
        if rx[i] == "\\":
            i += 1
        i += 1
    return i + 1


def _group_end(rx, i):
    """i points at a '('; return the index of its matching ')', or len(rx) if it is unbalanced."""
    depth, n = 0, len(rx)
    while i < n:
        c = rx[i]
        if c == "\\":
            i += 2
            continue
        if c == "[":
            i = _skip_class(rx, i)
            continue
        if c == "(":
            depth += 1
        elif c == ")":
            depth -= 1
            if depth == 0:
                return i
        i += 1
    return n


def _capture_span(rx, n=1):
    """(open, close) indices of the nth capturing group's parens, or None.

    `(...)` and `(?P<name>...)` capture; `(?:`  `(?=`  `(?i:` do not. Left-to-right including
    nested groups, which is exactly how `re` numbers them, so n lines up with `m.group(n)`.
    """
    i, end, count = 0, len(rx), 0
    while i < end:
        c = rx[i]
        if c == "\\":
            i += 2
            continue
        if c == "[":
            i = _skip_class(rx, i)
            continue
        if c == "(":
            if rx[i + 1:i + 2] != "?" or rx[i + 2:i + 4] == "P<":
                count += 1
                if count == n:
                    return (i, _group_end(rx, i))
            i += 1          # descend: the next capture may be nested inside this group
            continue
        i += 1
    return None


def _first_group(rx):
    """(open, close) indices of the leftmost capturing group's parens, or None."""
    return _capture_span(rx, 1)


def _alternatives(body):
    """Split a group body on its top-level | ."""
    out, depth, cur, i, n = [], 0, [], 0, len(body)
    while i < n:
        c = body[i]
        if c == "\\":
            cur.append(body[i:i + 2])
            i += 2
            continue
        if c == "[":
            j = _skip_class(body, i)
            cur.append(body[i:j])
            i = j
            continue
        if c == "(":
            depth += 1
        elif c == ")":
            depth -= 1
        elif c == "|" and depth == 0:
            out.append("".join(cur))
            cur = []
            i += 1
            continue
        cur.append(c)
        i += 1
    out.append("".join(cur))
    return out


def secret_group(regex):
    """Which group of `regex` holds the credential: the leftmost capture, or 0 for the whole match.

    gitleaks' own default is the whole match; `secretGroup = N` is its override. Most vendored
    rules do wrap exactly the value in their leftmost capture, so that is the useful default --
    group 0 would drag the `api_key = "` prefix and the trailing delimiter into the vault. But
    the leftmost capture is demonstrably NOT the value when it is
      * quantified            -- microsoft-teams-webhook's ([a-z0-9]{4}-){3}, or
      * only fixed literals   -- jwt-base64's (?P<alg>aGJHY2lPaU), sonar-api-token's (login|token)
    and trusting it there hands the live credential back in the rewrite. Over-capturing the whole
    match is merely untidy; under-capturing leaks.
    """
    span = _first_group(regex)
    if span is None:
        return 0
    open_i, close_i = span
    body = regex[open_i + 1:close_i]
    if body.startswith("?P<") and ">" in body:
        body = body.split(">", 1)[1]
    if regex[close_i + 1:close_i + 2] in ("*", "+", "?", "{"):
        return 0
    for alt in _alternatives(body):
        if alt == "" or any(c in _META for c in alt):
            return 1   # a real pattern, not a fixed marker
    return 0


# --- confidence tiers ---------------------------------------------------------------------------
# Characters a pattern matches literally AND that a vendor marker is made of: ASCII alphanumerics
# plus _ and - . Everything else ends the run -- an escape (`hvs\.`), a character class
# (`AKIA[A-Z2-7]{16}`), a quantified atom (`https?`) -- because the run has to be text that EVERY
# match is guaranteed to open with.
_LITERAL_RUN = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-")
# Zero-width escapes: walk past them, they match no text. `\b` heads most vendored patterns.
_ZERO_WIDTH = frozenset("bBAZ")
# Three characters, which is exactly what the previous test -- `[A-Za-z0-9]{2,}[_-]` -- also
# demanded. So the floor is unchanged and only the requirement that the third character be a
# separator goes away. Two would promote `s3`, `hm` and any two-letter word a vendor writes.
MIN_LITERAL_RUN = 3
# A guard, not a limit anything real reaches: the deepest head-nesting in the shipped 221 is 2.
_MAX_NESTING = 12


def _group_inner(body):
    """A group body with its `?:` / `?i:` / `?P<name>` opener removed, or None if it matches nothing."""
    if not body.startswith("?"):
        return body
    if body.startswith("?P<") and ">" in body:
        return body.split(">", 1)[1]
    if ":" in body:
        return body.split(":", 1)[1]
    return None                  # a bare flag group like (?i) -- zero-width


def _past_quantifier(rx, i):
    """Index just past any quantifier at i, including a lazy or possessive marker."""
    n = len(rx)
    if i < n and rx[i] in "?*+":
        i += 1
    elif i < n and rx[i] == "{":
        j = rx.find("}", i)
        if j != -1:
            i = j + 1
    if i < n and rx[i] in "?+":
        i += 1
    return i


def _leading_literal(rx, depth=0):
    """How many fixed characters every string this fragment matches is guaranteed to open with.

    Guaranteed is the whole point, so this is deliberately a lower bound and stops early rather
    than reasoning further:
      * a quantified literal ends the run BEFORE it (`https?` counts 4, not 5; `A{2}` counts 0),
        because a `?` makes it optional and a `{n}` moves everything after it;
      * an alternation contributes the MINIMUM over its branches, so one branch that pins nothing
        makes the whole head pin nothing -- vault-service-token's `s\\.` branch, and
        sourcegraph-access-token's bare `[a-fA-F0-9]{40}` branch, which is every git SHA there is.
        A top-level `|` is split BEFORE walking, because a group body carries its alternation
        unwrapped: `(sgp_...|sgp_...|[a-fA-F0-9]{40})` reads 4 from its first branch alone otherwise,
        which is the sourcegraph rule reading "confident vendor match" on every commit hash;
      * an optional group is compared against being absent as well, so
        `(?:https?://)?hooks.slack.com/` still counts 4 rather than 0.
    """
    if depth > _MAX_NESTING:
        return 0
    alts = _alternatives(rx)
    if len(alts) > 1:
        return min(_leading_literal(a, depth + 1) for a in alts)
    i, n, run = 0, len(rx), 0
    while i < n:
        c = rx[i]
        if c in "^$":
            i += 1                                        # anchors match no text
            continue
        if c == "\\":
            if rx[i + 1:i + 2] in _ZERO_WIDTH:
                i += 2
                continue
            return run                                    # \. \/ \x60 -- a literal, but not one of ours
        if c == "(":
            close = _group_end(rx, i)
            if rx[i + 1:i + 2] == "?" and rx[i + 2:i + 3] in ("=", "!", "<"):
                i = close + 1                             # lookaround: zero-width
                continue
            body = _group_inner(rx[i + 1:close])
            if body is None:
                i = close + 1
                continue
            rest = rx[_past_quantifier(rx, close + 1):]
            alts = _alternatives(body)
            quant = rx[close + 1:]
            if quant[:1] in ("?", "*") or quant[:3] in ("{0,", "{0}"):
                return run + min([_leading_literal(a + rest, depth + 1) for a in alts]
                                 + [_leading_literal(rest, depth + 1)])
            return run + min(_leading_literal(a, depth + 1) for a in alts)
        if c in _LITERAL_RUN:
            nxt = rx[i + 1:i + 2]
            if nxt and nxt in "?*{":
                return run
            run += 1
            i += 1
            if nxt == "+":
                return run                                # one is guaranteed, the offset after is not
            continue
        return run
    return run


def classify(regex, group=None):
    r"""Return "high" if the value this rule captures OPENS with a fixed literal, else "low".

    Only the secret group's own content counts -- the text that ends up in the vault. That anchor
    is what makes a bare three-character literal safe to accept without a trailing separator:

      * three fixed characters ANYWHERE in the value half instead reads `curl` out of
        curl-auth-user, `kind:`/`secret` out of kubernetes-secret-yaml and `gems.contribsys.com`
        out of sidekiq-sensitive-url. In each of those the literal sits OUTSIDE the captured group,
        so the credential clowk files carries no vendor evidence at all. Measured across the
        shipped 221: those three were the only false highs a position-blind version produced.
      * the anchor also subsumes the protection this used to get by splitting the pattern on
        gitleaks' `keyword <operator> value` operator and classifying the tail.
        hashicorp-tf-password's alternation is (?:administrator_login_password|password), and
        `administrator_` used to read as a pinned vendor prefix, so a plain
        `password = "localdevonly1"` blocked at "high" -- suppressing the very "shape-only match,
        run clowk clear NAME" hint it needed. Its group 1 opens with `"`, so reading the group
        answers that with no split, and answers it for a keyword sitting AFTER the value too,
        which a split cannot.

    Dropping the separator requirement is the fix. `[A-Za-z0-9]{2,}[_-]` recognised ghp_, xoxb-
    and sk_live_ but not AKIA, AIza, LTAI, dapi, sha256~ or -----BEGIN: 26 rules, every one a
    genuinely pinned vendor format, told the user "shape-only guess, `clowk clear NAME` if wrong"
    -- i.e. offered to delete a working credential. Both halves of the change are needed: without
    the anchor the separator was the only thing keeping `curl` out.

    `group` is which group holds the value. It defaults to secret_group(regex), but a caller that
    knows better must pass it, because gitleaks' own `secretGroup = N` overrides the heuristic.
    sonar-api-token is why: it declares group 2, its leftmost capture is the fixed `(login|token)`,
    and classifying the whole pattern instead reads the keyword `sonar` as the pinned prefix. Its
    group 2 is `(?:squ_|sqp_|sqa_)?[a-z0-9=_-]{40}`, whose prefix is OPTIONAL, so
    `sonar.login = <40 characters of anything>` matches carrying no marker.

    A group of 0 means the whole match is the value, so there is no keyword half to exclude and the
    whole pattern is read. That is sound only while no whole-match rule carries the keyword
    template; true of all 221 today, and test_tiers fails if a refresh changes it.
    """
    if group is None:
        group = secret_group(regex)
    body = regex
    if group:
        span = _capture_span(regex, group)
        if span is not None:
            body = _group_inner(regex[span[0] + 1:span[1]]) or ""
    return "high" if _leading_literal(body) >= MIN_LITERAL_RUN else "low"


# --- naming a generic match ---------------------------------------------------------------------
# generic-api-key is the one vendored rule whose env name describes the RULE rather than the
# credential -- every other one of the 221 names a vendor or a format (STRIPE_SECRET_KEY, JWT,
# PRIVATE_KEY, CURL_AUTH_HEADER). It is also the only one that matched BECAUSE OF A LABEL THE USER
# TYPED: its pattern is `<keyword><operator><value>`, so a match proves a credential word sits
# right beside the value. That was thrown away and replaced with the constant.
#
# Reported from real use: an AWS secret access key pasted as `secrate access key = <value>` was
# filed as $GENERIC_API_KEY. There is no AWS secret-key rule in the vendored set and a 40-char
# base64 blob has no pinnable shape, so falling through to the generic rule is right -- naming it
# after the rule is not. The words `access key` were in the matched text all along.
#
# The name is built ONLY out of characters the regex matched, which is what makes it independent of
# spelling: the reported paste also misspelled "secrate", the match therefore begins at "access",
# and the name is ACCESS_KEY. Spelled correctly it is SECRET_ACCESS_KEY. Nothing here needs a
# dictionary, a stem list or a fuzzy compare -- the keyword alternation gitleaks already ships is
# the vocabulary, and a match through it is the evidence.
GENERIC_ID = "generic-api-key"
# Words, not characters: the matched context is `secret_access_key = ` or `api_key": "` or
# `Api-Key: `, and splitting on non-alphanumerics turns all three into the name a human would have
# typed. Digits are kept inside a word (KEY2) but a name may not START with one -- see label_env.
_LABEL_WORD = re.compile(r"[A-Za-z0-9]+")
# The credential words, and NOT a vocabulary of clowk's own invention: these are the stems of
# generic-api-key's own keyword alternation --
#   (?:access|auth|(?-i:[Aa]pi|API)|credential|creds|key|passw(?:or)?d|secret|token)
# -- shortened only where one stem covers a family the rule already accepts, so `cred` covers creds
# and credentials, `pass` covers passwd and password, `auth` covers authorization. A rule's own
# gate is the only defensible answer to "which words mean credential here".
_LABEL_STEMS = ("access", "api", "auth", "cred", "key", "pass", "secret", "token")
# The matched context is bounded by the rule itself -- a keyword, then at most 20 characters of
# `[ \t\w.-]`, then the operator -- so 40 is a backstop rather than a working limit. Over it,
# falling back beats truncating: a truncated name is unpredictable and can collide with a different
# credential's, and vault.store's suffixing can only tell values apart, not intentions.
MAX_LABEL = 40
# Three, so a stray one- or two-letter token cannot become a $NAME. The shortest real label is
# `key`, which is exactly three.
MIN_LABEL = 3


def label_env(context, fallback):
    """The $NAME a credential's own adjacent label suggests, or `fallback` if there is none usable.

    The name is the longest UNBROKEN run of credential words ending at the last one. Both halves of
    that are paid for by a measurement:

      * credential words only, because gitleaks' template allows 20 characters of `[ \\t\\w.-]`
        between the keyword and the operator, and a whole clause fits through that hole. Taking
        every word filed README's own headline example -- `rotate this key for me: <key>` -- as
        $KEY_FOR_ME, and `the token for staging: <key>` as $TOKEN_FOR_STAGING. Found by rendering
        the block message and reading it, which is the only way that kind of thing is ever found.
      * unbroken and ending at the last one, because a run merely spanning first to last drags the
        clause back in whenever a credential word sits on both sides of it: `key for the token`
        would be KEY_FOR_THE_TOKEN. Ending at the LAST one is also what English does -- the noun
        is at the end, so `my access key for prod` is an ACCESS_KEY and `auth_token_hint` is an
        AUTH_TOKEN.

    Deliberately total and deliberately dull otherwise: it reads a short, already-matched string and
    either returns an UPPER_SNAKE_CASE identifier or gives up. Every rejection matters --

      * no credential word at all (`= '`, `hostname = `) -- nothing here names a credential;
      * a leading digit -- not a legal shell identifier, and `$(clowk get 2FA)` would fail looking
        like a bad credential rather than a bad name;
      * under MIN_LABEL or over MAX_LABEL -- too short to mean anything, or long enough to be prose.

    -- because the alternative to a good name is not a bad name, it is the rule's own name, which is
    at least honest. It never invents: every character of the result was typed by the user.
    """
    words = _LABEL_WORD.findall(context)
    last = -1
    for i, word in enumerate(words):
        if word.lower().startswith(_LABEL_STEMS):
            last = i
    if last < 0:
        return fallback
    first = last
    while first and words[first - 1].lower().startswith(_LABEL_STEMS):
        first -= 1
    name = "_".join(w.upper() for w in words[first:last + 1])
    if not name[0].isalpha() or not MIN_LABEL <= len(name) <= MAX_LABEL:
        return fallback
    return name


def _shannon(s):
    if not s:
        return 0.0
    freq = {c: s.count(c) for c in set(s)}
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in freq.values())


# --- standalone credential tokens -------------------------------------------------------------
# The vendored gitleaks rules split into two kinds. 114 of the 221 pin a literal vendor prefix in the
# value they capture -- ghp_, sk_live_, xoxb-, AKIA -- so a bare paste can fire them with no keyword
# anywhere near. 101 of the 221 instead need `keyword <operator> value` verbatim, which is a SOURCE
# CODE shape -- and clowk's whole job is catching what a human types into a chat, where people write
# "here's the api key - VALUE", "my api key is VALUE", or just paste the value alone. Measured on a
# labelled corpus, the shipped ruleset caught 11 of 20 realistic pastes: every miss was a prefix-less
# credential in natural language.
#
# (The first count has been 96, then 91, and is now 114 -- twice because classify() was wrong, not
# because the ruleset changed. Every number here is derived by test_tiers, which is the only reason
# they are trustworthy: the two earlier corrections both left this comment stale.)
#
# This rule closes that, with no keyword requirement at all. It is one of the three rules clowk adds
# to the vendored set, and it is tagged "low" because a bare token carries no vendor evidence.
#
# The discriminator is that ordinary high-entropy text in a developer's prompt is overwhelmingly
# single-case hex (git SHAs, md5, sha256, request ids) or carries a structural marker (sha256:,
# base64,), while real credentials mix case and digits. Validated against 704 prompts the author
# had actually typed to agents: 3 hits, all 3 genuine secrets, no false positives.
STANDALONE_ID = "clowk-standalone-token"
# Not derived from a nearby label, unlike generic-api-key's -- and that is a decision, not an
# omission. This rule requires no keyword, so its match carries none: there is nothing that
# "actually matched" to read a name out of. Deriving one would mean scanning a window of prompt
# text the rule never looked at, which is a different mechanism with a worse failure mode -- it
# would name a credential after whatever word happened to precede it, and it would give the SAME
# value different names in different pastes ($SECRET here, $API_KEY there), which is exactly the
# instability the generic-rule fix is careful to avoid. Measured on the labelled corpus: 8 of the
# 10 prose positives do land here with a credential word visible earlier in the prompt, so this
# gives something up. It is recorded as a limitation rather than guessed at.
STANDALONE_ENV = "SECRET"
# 3.5 is the floor gitleaks uses for its own generic rule, so this matches the vendored set
# rather than being tuned. Shannon entropy is capped at log2(len), which is only 4.58 for a
# 24-char token -- a 4.0 floor sat above the 5th percentile of real 128-bit base64 keys and
# dropped 7% of them. Measured across 3.4-3.8 the choice makes no difference to precision.
MIN_ENTROPY = 3.5

# Upper bound covers a 2048-bit secret: 256 random bytes is 512 hex chars or 342 base64 chars.
# A 64-char cap -- the obvious first guess -- silently missed every key of 512 bits or more,
# including a Rails secret_key_base (128 hex) and any base64-encoded 512-bit secret (86 chars).
MAX_TOKEN = 512

# A complete ANSI CSI sequence -- ESC [ parameters final-byte, per ECMA-48, whose final byte is any
# of \x40-\x7e. This is a TOKEN BOUNDARY, and it has to be a consuming alternative rather than part
# of the lookbehind below, for two reasons that pull in opposite directions:
#
#   * `[` cannot simply join the lookbehind's exclusion set. With `ESC[1m` glued to a value the
#     match used to start at the `1` and swallow `1m`, so the filed value was `1m<key>` -- no leak,
#     the whole span is redacted, but `clowk get` handed back a credential that would not work,
#     which is the rotation bug's failure mode wearing a different hat. Excluding `[` does not fix
#     that: it blocks the start at `1`, and then `m` is preceded by `1` and `<key>` by `m`, both
#     word characters, so every later start is blocked too and the credential is not detected AT
#     ALL. The same trap the first-character note above records.
#   * a lookbehind cannot express it either, because `re` needs a fixed width and an escape
#     sequence has none -- `ESC[m` is 3 characters, `ESC[38;5;214m` is 12.
#
# So the sequence is consumed by an alternative that carries no lookbehind of its own, which is
# also correct: an escape sequence IS a boundary, so what precedes it cannot matter. Group 1 is
# still the token, so every span and every downstream use is unchanged.
_CSI = r"\x1b\[[0-9;?]*[\x40-\x7e]"
# The other half, and it is not redundant. The alternative above only helps when the CLEAN token
# clears the 20-character floor; when it does not, the whole alternative fails, the scan falls back
# to a later start position inside the sequence, and `ESC[1m` + a 19-character run matches as a
# 21-character `1m<run>` again. Nor can the alternative help at all for a long parameter list:
# `ESC[38;5;214m` + a short run starts at the `2` of `214`, whose preceding character is `;`.
#
# So a match whose START lands inside a CSI sequence -- everything back to the introducer being
# parameter bytes -- is dropped. The pair is what makes the rule exact: the alternative FINDS the
# real token, this drops the escape's own tail, and neither alone is enough. Dropping alone would
# be a leak (the long case would go undetected); finding alone leaves the short case corrupt.
_CSI_OPEN = re.compile(r"\x1b\[[0-9;?]*$")
# Enough for the introducer plus 30 parameter bytes. A CSI sequence longer than that is not
# something a terminal writes around text, and if one existed the fallback is today's behaviour.
_CSI_LOOKBACK = 32
# 20-512 chars, not glued to a path, URL, version string or assignment. +/= are allowed because
# base64 secrets contain them, which is also why the decodes-to-text check below has to exist.
# The FIRST character accepts + and / too: those are in the base64 alphabet, so ~3% of keys
# start with one, and requiring an alphanumeric there made them unmatchable -- the lookbehind
# then blocks every later start position, so the token was skipped entirely rather than trimmed.
_TOKEN = re.compile(r"(?:%s|(?<![\w./:=+-]))([A-Za-z0-9+/][A-Za-z0-9_+/=-]{19,%d})(?![\w./=+-])"
                    % (_CSI, MAX_TOKEN - 1))
_UUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I)
_HEX_ONLY = re.compile(r"^[0-9a-f]+$", re.I)
_LOWER = re.compile(r"[a-z]")
_UPPER = re.compile(r"[A-Z]")
_DIGIT = re.compile(r"[0-9]")

# A preceding marker that says "this is a digest, not a credential".
_STRUCTURAL = ("sha256:", "sha512-", "sha512:", "sha1-", "sha1:", "md5:", "base64,")

# Infrastructure id namespaces. These are mixed-case and high-entropy, so they look exactly like
# credentials, and they are not. Without this, 79 of 704 real prompts matched -- every one an
# agent-harness tool-use id echoed back in a notification. Blocking those would have wedged the
# session on messages the user never typed.
_NAMESPACES = (
    "toolu_", "msg_", "req_", "run_", "task_", "wf_", "call_", "asst_", "thread_",
    "evt_", "job_", "sess_", "span_", "trace_",
)


# --- credentials embedded in a connection URI ---------------------------------------------------
# scheme://user:password@host -- a database URL, a broker URL, a registry URL. This needs its own
# rule for two reasons, both found by a real paste that went straight through:
#
#   1. The standalone rule cannot see it. The character before the password is ":", which sits in
#      that rule's negative lookbehind -- the guard that stops it matching inside paths and URLs.
#      So the very construct most likely to carry a credential was the one it was blind to.
#   2. No vendored gitleaks rule covers connection strings; the closest are curl-auth-* and
#      sidekiq-sensitive-url, neither of which matches a bare postgresql:// URL.
#
# Confidence is HIGH, unlike the standalone rule: a password in a URI's userinfo section is not a
# shape that happens to look like a credential, it is definitionally one.
#
# The whole URL is captured, not just the password. Replacing only the password would leave the
# host, username and database name in the prompt -- internal topology the model does not need --
# and a single $DATABASE_URL is also how the value is actually consumed.
URI_ID = "clowk-connection-uri"
_URI = re.compile(
    r"\b([a-z][a-z0-9+.\-]{1,31}://[^\s:/?#\[\]@]+:([^\s/?#\[\]@]+)@[^\s/?#\[\]]+[^\s\"'<>]*)",
    re.I)

# scheme -> the env name a human would actually use for it
_URI_ENV = {
    "postgres": "DATABASE_URL", "postgresql": "DATABASE_URL", "mysql": "DATABASE_URL",
    "mariadb": "DATABASE_URL", "mssql": "DATABASE_URL", "sqlserver": "DATABASE_URL",
    "mongodb": "MONGODB_URI", "mongodb+srv": "MONGODB_URI",
    "redis": "REDIS_URL", "rediss": "REDIS_URL",
    "amqp": "AMQP_URL", "amqps": "AMQP_URL", "kafka": "KAFKA_URL",
    "clickhouse": "CLICKHOUSE_URL", "elasticsearch": "ELASTICSEARCH_URL",
    "ftp": "FTP_URL", "sftp": "SFTP_URL", "ssh": "SSH_URL",
    "http": "SERVICE_URL", "https": "SERVICE_URL",
}

# A placeholder password is not a credential. These are what documentation and .env.example use.
_URI_PLACEHOLDERS = frozenset((
    "password", "passwd", "pass", "secret", "changeme", "change_me", "your_password",
    "yourpassword", "xxx", "xxxx", "placeholder", "example", "test", "postgres", "root",
    "admin", "user", "username", "mypassword", "hunter2", "redacted", "none", "null",
))


def uri_findings(text):
    """Findings for scheme://user:password@host, capturing the whole URI."""
    out = []
    for m in _URI.finditer(text):
        uri, password = m.group(1), m.group(2)
        if _is_placeholder(password):
            continue
        scheme = uri.split("://", 1)[0].lower()
        env = _URI_ENV.get(scheme, "CONNECTION_URL")
        out.append(Finding(URI_ID, env, uri, m.start(1), m.end(1), "high"))
    return out


# --- credentials embedded in a key=value; connection string --------------------------------------
# The other half of the same idea, and it was missing. An Azure storage string had its AccountKey
# replaced and kept `AccountName=prodstore;EndpointSuffix=core.windows.net`, which names the account
# to the model as plainly as the key would have -- exactly the leak the whole-URI capture above
# exists to prevent, in the dialect the URI rule cannot parse. `key=value;` is what every Microsoft
# SDK, every ODBC driver and every ADO.NET provider uses, and no vendored gitleaks rule covers it.
#
# Same treatment, therefore: capture the WHOLE string, high confidence, one env name a human would
# actually put in their shell. Not covered: the comma-delimited StackExchange.Redis dialect
# (`host:6380,password=...,ssl=True`), because a comma is far weaker evidence of a pair boundary
# than a semicolon and the value there is reachable through the keyword rules anyway.
KV_ID = "clowk-connection-string"

# The keys whose value is a credential, each with the product whose format uses it. Deliberately
# NOT bare `Key` or `Secret`: those are the map-key sense as often as the credential sense, and the
# key has to match a whole segment, so `PartitionKey=` and `SharedAccessKeyName=` are not these.
_KV_CREDENTIAL_KEYS = (
    "accountkey",            # Azure Storage, Cosmos DB
    "sharedaccesskey",       # Service Bus, Event Hubs, IoT Hub, Relay -- the SAS key
    "accesskey",             # Azure SignalR, Web PubSub
    "secretkey",             # MinIO / Ceph / S3-compatible `AccessKey=...;SecretKey=...`
    "primarykey", "secondarykey",   # Notification Hubs and assorted Azure key listings
    "password", "pwd",       # ADO.NET, ODBC, JDBC: SQL Server, MySQL, Db2, Oracle, Snowflake
    "clientsecret",          # Azure AD service-principal strings
    "apikey", "api key",     # Azure Search and assorted SDK strings
    "application key",       # Azure Data Explorer (Kusto)
)

# A pair is `key=value`. The value stops at a semicolon, whitespace or a quote, so a string
# embedded in JSON or in a shell argument does not drag the closing quote into the vault.
_KV_VALUE = r"[^;\s\"'\x60]*"
# The FIRST key may not contain a space; later keys may. That asymmetry is the whole guard against
# swallowing prose: SQL Server really does write `Initial Catalog=` and `User ID=`, so spaces have
# to be legal somewhere -- but allowing them in the leading key made `look at Server=db;Pwd=x`
# match from `look`, filing the reader's own sentence as part of the credential.
_KV = re.compile(
    r"(?<![\w=&?/\-])("                                    # not glued into a word or a query string
    r"[A-Za-z][A-Za-z0-9_.\-]{0,38}=" + _KV_VALUE +        # first pair, space-free key
    r"(?:[ \t]*;[ \t]*[A-Za-z][A-Za-z0-9_.\- ]{0,38}=" + _KV_VALUE + r")+"   # 1+ further pairs
    r")")
# Which of those pairs carries the credential, read back out of the (short) matched string.
_KV_CREDENTIAL = re.compile(
    r"(?:^|;)[ \t]*(?:%s)[ \t]*=[ \t]*(%s)"
    % ("|".join(k.replace(" ", r"\s") for k in _KV_CREDENTIAL_KEYS), _KV_VALUE), re.I)

# Ordered, because several apply at once: an Azure storage string carries both AccountKey and
# DefaultEndpointsProtocol, and a Cosmos string carries AccountKey too. First match wins.
_KV_ENV = (
    ("accountendpoint=", "COSMOS_CONNECTION_STRING"),
    ("azure-devices.net", "IOT_HUB_CONNECTION_STRING"),
    ("signalr.net", "SIGNALR_CONNECTION_STRING"),
    ("webpubsub.azure.com", "WEB_PUBSUB_CONNECTION_STRING"),
    ("servicebus.windows.net", "SERVICE_BUS_CONNECTION_STRING"),
    ("endpoint=sb://", "SERVICE_BUS_CONNECTION_STRING"),
    ("defaultendpointsprotocol=", "AZURE_STORAGE_CONNECTION_STRING"),
    ("blob.core.windows.net", "AZURE_STORAGE_CONNECTION_STRING"),
    ("accountname=", "AZURE_STORAGE_CONNECTION_STRING"),
    ("sharedaccesskey=", "SERVICE_BUS_CONNECTION_STRING"),
    ("accountkey=", "AZURE_STORAGE_CONNECTION_STRING"),
    ("data source=", "DATABASE_CONNECTION_STRING"),
    ("server=", "DATABASE_CONNECTION_STRING"),
    ("database=", "DATABASE_CONNECTION_STRING"),
    ("initial catalog=", "DATABASE_CONNECTION_STRING"),
    ("driver=", "ODBC_CONNECTION_STRING"),
    ("dsn=", "ODBC_CONNECTION_STRING"),
)

# Anything a value can be wrapped in when it is a template rather than a credential.
_TEMPLATE_WRAPPERS = "<>{}[]()*\"' \t"
# Only prefixes of four characters or more. "my" would read 0.1% of real base64 keys as a
# placeholder -- a worse miss rate than the entropy tail this project has spent commits on.
_PLACEHOLDER_PREFIXES = (
    "your", "insert", "replace", "example", "sample", "dummy", "todo", "fixme", "changeme",
    "mypassword", "mysecret", "myaccount", "mykey", "some-", "some_",
)


def _is_placeholder(value):
    """True if this is documentation's idea of a credential rather than one.

    Shared by both connection-string rules: the same `<your-key>`, `{{password}}`, `$DB_PASS`,
    `***REDACTED***` and `xxxxxxxx` turn up in a URI's userinfo and in a `key=value;` pair alike.
    """
    v = value.strip(_TEMPLATE_WRAPPERS)
    if not v:
        return True                                   # `Password=;` -- nothing was filled in
    if v[0] in "$%":
        return True                                   # already a reference: $DB_PASS, %DB_PASS%
    low = v.lower()
    if low in _URI_PLACEHOLDERS or low.startswith(_PLACEHOLDER_PREFIXES):
        return True
    return set(low) <= set("x*.-_")                   # xxxxxxxx, ********, --------


def kv_findings(text):
    """Findings for `key=value;key=value;` connection strings, capturing the whole string."""
    out = []
    for m in _KV.finditer(text):
        conn = m.group(1)
        values = [c.group(1) for c in _KV_CREDENTIAL.finditer(conn)]
        if not values or all(_is_placeholder(v) for v in values):
            continue          # a config dump, a CSS declaration, or a template with nothing in it
        env = "CONNECTION_STRING"
        low = conn.lower()
        for marker, name in _KV_ENV:
            if marker in low:
                env = name
                break
        out.append(Finding(KV_ID, env, conn, m.start(1), m.end(1), "high"))
    return out


def _decodes_to_text(tok):
    """True if this base64-decodes to readable ASCII, i.e. it is encoded TEXT, not a key.

    A credential's bytes are random, so its base64 decodes to mostly unprintable bytes -- measured
    at 0.36-0.38 printable for real keys against 1.00 for encoded prose. Without this, someone
    pasting `Zm9vYmFyYmF6...  -- decode this for me` gets their turn blocked, which is a normal
    thing to ask an agent to do.
    """
    padded = tok + "=" * (-len(tok) % 4)
    try:
        raw = base64.b64decode(padded, validate=True)
    except (binascii.Error, ValueError):
        return False                      # not base64 at all, so this test says nothing
    if len(raw) < 8:
        return False
    printable = sum(1 for b in bytearray(raw) if 32 <= b <= 126)
    return printable / float(len(raw)) > 0.85


def standalone_findings(text):
    """Findings for credential-shaped tokens that stand alone, with no keyword anywhere near.

    Hex-only tokens are deliberately NOT reported here, and that is a real limitation rather than
    an oversight: a 64-character hex string is shape-identical to a sha256 digest, and a 40-char
    one to a git object id. Nothing about the token separates a 256-bit HMAC secret from a hash, so
    reporting them would block `git show <sha>`. Hex secrets are reachable only through a keyword,
    which is why the keyword rules accept prose operators -- see build_rules.py.
    """
    out = []
    for m in _TOKEN.finditer(text):
        tok = m.group(1)
        # The marker can sit either just before the token (`base64,AAAA`) or inside it, when the
        # token boundary opens on a quote: `"sha512-oGMAgG..."` matches from the s, so the marker
        # becomes a prefix of the token rather than context around it. Checking only one of those
        # let every npm lockfile integrity hash read as a credential.
        lowered = tok.lower()
        before = text[max(0, m.start(1) - 12):m.start(1)].lower()
        if any(marker in before or lowered.startswith(marker) for marker in _STRUCTURAL):
            continue
        if _CSI_OPEN.search(text[max(0, m.start(1) - _CSI_LOOKBACK):m.start(1)]):
            continue          # this run is an ANSI escape's parameter tail, not a credential
        if any(tok.startswith(ns) for ns in _NAMESPACES):
            continue
        if _UUID.match(tok) or _HEX_ONLY.match(tok):
            continue
        if not (_LOWER.search(tok) and _UPPER.search(tok) and _DIGIT.search(tok)):
            continue
        if _shannon(tok) < MIN_ENTROPY:
            continue
        if _decodes_to_text(tok):
            continue
        out.append(Finding(STANDALONE_ID, STANDALONE_ENV, tok, m.start(1), m.end(1), "low"))
    return out


def compile_rules(rules):
    """Compile once, defensively. A rule this Python cannot use is skipped, never fatal.

    The catch is deliberately wide: rules.json is plaintext that users do edit, and an entry that
    is a bare string or is missing "regex" raises TypeError/KeyError, not re.error. Losing one
    hand-mangled rule is acceptable; losing all 221 is the fail-open this module exists to avoid.
    """
    out = []
    for r in rules:
        try:
            pat = re.compile(r["regex"], re.I if r.get("ignorecase") else 0)
            if not (r.get("id") and r.get("env")):
                continue                        # scan() needs both; reject here, not mid-scan
            g = r.get("group")                  # precomputed by build_rules.py
            if g is None:
                g = secret_group(r["regex"])    # hand-edited rules.json: derive, never guess 1
            out.append((r, pat, g if isinstance(g, int) and 0 <= g <= pat.groups else 0))
        except Exception:  # noqa: BLE001 -- re.error, TypeError, KeyError, ...
            continue
    return out


_COMPILED = compile_rules(RULES)

if not _COMPILED and not RULESET_ERROR:
    RULESET_ERROR = "no rule in %s could be compiled" % RULES_PATH
if RULESET_ERROR:
    # Loud, not silent: a degraded ruleset means clowk scans nothing, and a hook that looks
    # healthy while protecting nothing is worse than one that says so. stderr, not a raise, and
    # not a block -- the exit code alone decides whether a turn is blocked.
    try:
        sys.stderr.write("clowk: %s -- NOT scanning for credentials\n" % RULESET_ERROR)
    except Exception:  # noqa: BLE001 -- a detached stderr must not break the hook either
        pass


# A hex secret cannot clear an entropy floor that was calibrated for base64. gitleaks' floors --
# 1.0 to 4.5 across the 130 vendored rules that carry one, every one of them also keyword-gated --
# are absolute numbers tuned against alphabets whose Shannon ceiling is log2(64) = 6.0. Hex has 16
# symbols, so it caps at 4.0, and the SAME number therefore means something far stricter there.
# Measured over 2000 random keys behind `webhook_secret = `: 128-bit hex cleared the 3.5 floor only
# 81.05% of the time, 160-bit 94.8%, 256-bit 99.8% (1 in 4,650 over 400,000). Those misses are
# unrecoverable -- the credential reaches the model -- while a false positive costs the user one
# `unclowk` resend, so the asymmetry says fix the gate rather than document the tail.
#
# So a hex value of at least 128 bits may clear the floor OR show 8 distinct hex digits, which is
# what the floor was reaching for anyway: on a fixed alphabet, entropy is mostly a proxy for how
# much of that alphabet appears. Both halves are load-bearing:
#
#   * 8 distinct digits sits one symbol under the smallest count seen in 100,000 random 128-bit
#     hex strings (9), so full recall is a property of the gate rather than of the sample size --
#     256-bit never fell below 12. It still rejects everything placeholders are made of: "a"*32,
#     "0"*32, "f"*40, "ab"*16, "deadbeef"*4, "aaaaaaaabbbbbbbbccccccccdddddddd".
#   * OR, not INSTEAD OF, because four vendored rules are hex-only BY CONSTRUCTION and set a
#     deliberately permissive floor of 2.0 for it -- cloudflare-api-key (37 hex), adobe-client-id
#     and discord-client-secret (32), linear-client-secret (64). Replacing their floor outright
#     would have dropped a real Cloudflare key with only 7 distinct digits. Additive cannot
#     regress recall anywhere; a replacement can, on exactly the rules that need it least.
#   * 128 bits, i.e. 32 hex characters, because below that the absolute floor doubles as a LENGTH
#     guard -- 10 hex characters cannot reach 3.5 bits at all, since log2(10) = 3.32 -- and
#     dropping that guard is not free. With no length condition, 64-bit hex behind a keyword went
#     from 9% caught to 99.4%, and the repo's 1800-line log fixture went from 168 findings to
#     1782, because a 16-hex `auth_token_hint=` is one keyword away from every log line anyone
#     pastes. hook_prompt.capture() redacts with one str.replace per finding, so its cost is
#     O(findings x prompt length): on a 2 MB paste that took the whole hook from 3.2s to 46.0s,
#     against Claude Code's 60s hook timeout -- and past the timeout every host fails open and
#     transmits the credential. A precision question quietly became a fail-open one. 128 bits is
#     also the smallest key size anyone actually ships, so the recall given up is theoretical.
#
# It does accept a keyboard walk -- "1234567890abcdef" doubled -- but so does the floor it extends,
# at the maximum 4.0 bits, so that concession is inherited rather than new. Separating a walk from
# a key needs a per-symbol frequency model, which is a far larger change than the one miss it buys.
#
# REJECTED: scaling each floor by the observed alphabet, floor * log2(distinct)/6.0. It reaches
# 100% recall too and is unshippable -- "a"*32 has one symbol, so its floor scales to 0.0 and its
# entropy of 0.0 clears it. Every placeholder on earth passes.
# ALSO REJECTED: rescaling by the alphabet's CEILING instead, floor * 4.0/6.0 for hex. That one is
# sound and reaches 100% from 64 bits up, but it opens the same short-hex floodgate as dropping
# the length condition (1800 findings on the log fixture) for key sizes nobody ships.
#
# standalone_findings() is untouched and still excludes hex-only tokens outright: with no keyword
# beside it, a 64-char hex string is a sha256 digest and a 256-bit HMAC secret at once, and
# reporting those would block `git show <sha>`. This gate only ever runs behind a keyword gate.
_MIN_HEX_KEY = 32        # hex characters, i.e. 128 bits
_MIN_HEX_SYMBOLS = 8     # distinct hex digits out of the 16 there are


def _passes_entropy(secret, floor):
    """gitleaks' entropy gate, plus a symbol count for hex the floor is miscalibrated against."""
    if _shannon(secret) >= floor:
        return True
    if len(secret) < _MIN_HEX_KEY or not _HEX_ONLY.match(secret):
        return False
    return len(set(secret.lower())) >= _MIN_HEX_SYMBOLS   # lower(): AbAb is 2 hex digits, not 4


def scan(text):
    """Return de-duplicated Findings for secrets in text."""
    low = text.lower()
    out = {}
    for r, pat, group in _COMPILED:
        kws = r.get("keywords")
        if kws and not any(k.lower() in low for k in kws):  # keyword gate (gitleaks optimization + FP cut)
            continue
        for m in pat.finditer(text):
            if group and m.group(group) is not None:
                secret, start, end = m.group(group), m.start(group), m.end(group)
            else:
                secret, start, end = m.group(0), m.start(0), m.end(0)
            if r.get("entropy") and not _passes_entropy(secret, r["entropy"]):
                continue
            if secret in out:
                continue     # first match of a value wins; skip before doing any work for it
            # `group` is the resolved one -- gitleaks' declared secretGroup where there is one --
            # so a hand-edited rules.json with no precomputed confidence classifies the same
            # group the value is actually taken from.
            conf = r.get("confidence") or classify(r["regex"], group)
            env = r["env"]
            if r["id"] == GENERIC_ID:
                # The keyword half of this match: everything the rule consumed before the value.
                # Bounded by the pattern, so this is a handful of characters, and it only runs for
                # a value not already claimed -- a pasted log trips this rule hundreds of times.
                env = label_env(text[m.start(0):start], env)
            out[secret] = Finding(r["id"], env, secret, start, end, conf)
    # Connection strings first among clowk's own rules: the whole string is the useful unit, and
    # claiming it before the standalone rule stops the password inside it being filed separately as
    # well. capture() then replaces the longest finding first, so the vendored rule that matched the
    # bare value inside one of these never gets to file it either.
    for finding in uri_findings(text):
        out.setdefault(finding.secret, finding)
    for finding in kv_findings(text):
        out.setdefault(finding.secret, finding)
    # Last, and only for values no vendored rule claimed: a rule that named the vendor is always
    # the better label, and setdefault keeps whichever landed first.
    for finding in standalone_findings(text):
        out.setdefault(finding.secret, finding)
    return list(out.values())
