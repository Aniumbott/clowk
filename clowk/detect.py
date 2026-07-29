"""Secret detection using the vendored gitleaks ruleset (rules.py).
Keyword-gated + entropy-filtered, matching gitleaks semantics to keep false positives low."""
import re, math, json, os
from collections import namedtuple

RULES = json.load(open(os.path.join(os.path.dirname(__file__), "rules.json")))

Finding = namedtuple("Finding", "rule_id env secret start end")

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
        if kws and not any(k.lower() in low for k in kws):   # keyword gate (gitleaks optimization + FP cut)
            continue
        for m in pat.finditer(text):
            if pat.groups and m.group(1) is not None:        # gitleaks puts the secret in group 1
                secret, start, end = m.group(1), m.start(1), m.end(1)
            else:
                secret, start, end = m.group(0), m.start(0), m.end(0)
            if r.get("entropy") and _shannon(secret) < r["entropy"]:
                continue
            out.setdefault(secret, Finding(r["id"], r["env"], secret, start, end))
    return list(out.values())
