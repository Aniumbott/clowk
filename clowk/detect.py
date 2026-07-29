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
from collections import namedtuple

RULES = json.load(open(os.path.join(os.path.dirname(__file__), "rules.json")))

Finding = namedtuple("Finding", "rule_id env secret start end confidence")

# A literal run of 2+ alphanumerics followed by _ or - , e.g. ghp_ , xoxb- , sk_live_ .
_LITERAL_PREFIX = re.compile(r"(?<![\\\[])([A-Za-z0-9]{2,}[_-])")
_CHAR_CLASS = re.compile(r"\[[^\]]*\]")


def classify(regex):
    """Return "high" if the pattern pins a literal vendor prefix, else "low"."""
    return "high" if _LITERAL_PREFIX.search(_CHAR_CLASS.sub("", regex)) else "low"


def _shannon(s):
    if not s:
        return 0.0
    freq = {c: s.count(c) for c in set(s)}
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in freq.values())


# compile once, defensively: any rule that won't compile on THIS Python is skipped, never crashes.
_COMPILED = []
for r in RULES:
    try:
        pat = re.compile(r["regex"], re.I if r.get("ignorecase") else 0)
    except re.error:
        continue
    _COMPILED.append((r, pat))


def scan(text):
    """Return de-duplicated Findings for secrets in text."""
    low = text.lower()
    out = {}
    for r, pat in _COMPILED:
        kws = r.get("keywords")
        if kws and not any(k.lower() in low for k in kws):  # keyword gate (gitleaks optimization + FP cut)
            continue
        for m in pat.finditer(text):
            if pat.groups and m.group(1) is not None:  # gitleaks puts the secret in group 1
                secret, start, end = m.group(1), m.start(1), m.end(1)
            else:
                secret, start, end = m.group(0), m.start(0), m.end(0)
            if r.get("entropy") and _shannon(secret) < r["entropy"]:
                continue
            conf = r.get("confidence") or classify(r["regex"])
            out.setdefault(secret, Finding(r["id"], r["env"], secret, start, end, conf))
    return list(out.values())
