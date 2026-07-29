"""Secret detection using the vendored gitleaks ruleset (rules.json).
Keyword-gated + entropy-filtered, matching gitleaks semantics to keep false positives low.

Confidence tiers: a rule whose regex carries a literal vendor prefix ending in _ or -
(ghp_, xoxb-, sk-ant-) is "high"; a shape-only rule is "low". Both still block -- blocking is
the only thing that prevents transmission -- but the tier changes the wording and lets
false-positive junk be purged from the vault later.

The test is deliberately narrow, so it is conservative rather than wrong: a prefix with no
trailing separator (AKIA...) or one buried in an alternation group ((?:sk|rk)_live_) reads as
"low" even though it is in fact a pinned vendor format. Never word a "low" message as "this is
probably not a credential" -- word it as "clowk is less sure what this is".
"""
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
        with open(path) as f:
            rules = json.load(f)
    except Exception as e:  # noqa: BLE001 -- missing/corrupt/unreadable; the type is the diagnosis
        return [], "cannot read %s (%s)" % (path, type(e).__name__)
    if not isinstance(rules, list) or not rules:
        return [], "%s is not a non-empty list of rules" % path
    return rules, ""


RULES, RULESET_ERROR = load_rules(RULES_PATH)

Finding = namedtuple("Finding", "rule_id env secret start end confidence")

# A literal run of 2+ alphanumerics followed by _ or - , e.g. ghp_ , xoxb- , sk_live_ .
_LITERAL_PREFIX = re.compile(r"(?<![\\\[])([A-Za-z0-9]{2,}[_-])")
_CHAR_CLASS = re.compile(r"\[[^\]]*\]")
# regex metacharacters: a group body free of all of them can only match one fixed string.
_META = frozenset("\\|.*+?[](){}^$")


def classify(regex):
    """Return "high" if the pattern pins a literal vendor prefix, else "low"."""
    return "high" if _LITERAL_PREFIX.search(_CHAR_CLASS.sub("", regex)) else "low"


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


def _first_group(rx):
    """(open, close) indices of the leftmost capturing group's parens, or None."""
    i, n, open_i, depth = 0, len(rx), None, 0
    while i < n:
        c = rx[i]
        if c == "\\":
            i += 2
            continue
        if c == "[":
            i = _skip_class(rx, i)
            continue
        if c == "(":
            if open_i is None and (rx[i + 1:i + 2] != "?" or rx[i + 2:i + 4] == "P<"):
                open_i, depth = i, 0   # (...) and (?P<name>...) capture; (?:  (?=  (?i:  do not
            elif open_i is not None:
                depth += 1
            i += 1
            continue
        if c == ")":
            if open_i is not None:
                if depth == 0:
                    return (open_i, i)
                depth -= 1
            i += 1
            continue
        i += 1
    return None


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


def _shannon(s):
    if not s:
        return 0.0
    freq = {c: s.count(c) for c in set(s)}
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in freq.values())


def compile_rules(rules):
    """Compile once, defensively. A rule this Python cannot use is skipped, never fatal.

    The catch is deliberately wide: rules.json is plaintext that users do edit, and an entry that
    is a bare string or is missing "regex" raises TypeError/KeyError, not re.error. Losing one
    hand-mangled rule is acceptable; losing all 220 is the fail-open this module exists to avoid.
    """
    out = []
    for r in rules:
        try:
            pat = re.compile(r["regex"], re.I if r.get("ignorecase") else 0)
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
            if r.get("entropy") and _shannon(secret) < r["entropy"]:
                continue
            conf = r.get("confidence") or classify(r["regex"])
            out.setdefault(secret, Finding(r["id"], r["env"], secret, start, end, conf))
    return list(out.values())
