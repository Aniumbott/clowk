#!/usr/bin/env python3
"""Build-time: convert vendored gitleaks.toml -> dependency-free rules.json.
Run once when updating the ruleset. Ships the generated rules.json so runtime needs no TOML parser.
ponytail: hand-parse the regular [[rules]] blocks instead of pulling a TOML dep for py<3.11.

Secret patterns are derived from gitleaks (https://github.com/gitleaks/gitleaks), MIT License."""
import re, json, os, sys, warnings

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from clowk.detect import classify, secret_group

_HERE = os.path.dirname(os.path.abspath(__file__))
SRC = os.path.join(_HERE, "clowk", "gitleaks.toml")
OUT = os.path.join(_HERE, "clowk", "rules.json")

# gitleaks rule id -> friendly env var name. Falls back to uppercased id for unmapped rules.
ENV_NAMES = {
    "github-pat": "GITHUB_TOKEN", "github-fine-grained-pat": "GITHUB_TOKEN",
    "github-oauth": "GITHUB_OAUTH_TOKEN", "github-app-token": "GITHUB_APP_TOKEN",
    "gitlab-pat": "GITLAB_TOKEN", "openai-api-key": "OPENAI_API_KEY",
    "anthropic-api-key": "ANTHROPIC_API_KEY", "aws-access-token": "AWS_ACCESS_KEY_ID",
    "stripe-access-token": "STRIPE_SECRET_KEY", "slack-bot-token": "SLACK_BOT_TOKEN",
    "slack-user-token": "SLACK_USER_TOKEN", "twilio-api-key": "TWILIO_API_KEY",
    "sendgrid-api-token": "SENDGRID_API_KEY", "mailgun-private-api-token": "MAILGUN_API_KEY",
    "gcp-api-key": "GCP_API_KEY", "digitalocean-pat": "DIGITALOCEAN_TOKEN",
    "npm-access-token": "NPM_TOKEN", "private-key": "PRIVATE_KEY", "jwt": "JWT",
}

def env_name(rule_id):
    if rule_id in ENV_NAMES:
        return ENV_NAMES[rule_id]
    return re.sub(r'[^A-Z0-9]+', '_', rule_id.upper()).strip('_')


# gitleaks' generic keyword-proximity template opens with lazy leading context, and five rules
# repeat it immediately inside their (?i:...) group. `finditer` already tries every start offset
# and the secret is always in a capture group, so this can only widen the reported match START --
# never decide whether the value is found. What it does cost is up to 50 (or 2500, doubled)
# backtrack states per input character: a 200KB paste that mentions "coherent" or "sumo" took 50s
# to find nothing, and 900KB crossed Claude Code's 60s default hook timeout, at which point every
# host fails open and transmits the credential. Anchored, so the same fragment appearing
# mid-pattern in a future gitleaks release is left alone -- there it is not redundant.
_LEADING_CONTEXT = re.compile(r'^(\(\?i:)?\[\\w\.-\]\{0,\d+\}\?')


# Go's regexp/syntax supports POSIX character classes inside a character class; Python's re does
# not -- it reads `[[:alnum:]]` as a nested set, which is a FutureWarning, which this script treats
# as a skip. So a rule using one was DROPPED, and the count in README quietly went down by one.
# That is how airtable-personnal-access-token -- `pat[[:alnum:]]{14}\.[a-f0-9]{64}`, the newest rule
# gitleaks has added -- was vendored and then never used: `pat<14>.<64 hex>` in prose was caught by
# nothing at all, and clowk's standalone rule cannot reach it either, because the dot in the middle
# ends its token.
#
# Translating is the same kind of dialect normalization as \z -> \Z above, and it is exactly what
# the class means -- no rule is loosened or tightened. Only [:alnum:] appears in today's config; the
# rest are here because the failure mode is a rule that vanishes rather than one that errors, and
# the next gitleaks release is not going to announce which class it used.
_POSIX_CLASSES = {
    '[:alnum:]': 'A-Za-z0-9', '[:alpha:]': 'A-Za-z', '[:digit:]': '0-9',
    '[:lower:]': 'a-z', '[:upper:]': 'A-Z', '[:xdigit:]': '0-9A-Fa-f',
    '[:word:]': r'\w', '[:space:]': r'\s', '[:blank:]': r' \t',
}


def translate_posix_classes(rx):
    """`[[:alnum:]]` -> `[A-Za-z0-9]`. Returns (regex, list of classes translated)."""
    found = [name for name in _POSIX_CLASSES if name in rx]
    for name in found:
        rx = rx.replace(name, _POSIX_CLASSES[name])
    return rx, found


def strip_leading_context(rx):
    """Drop the redundant leading `[\\w.-]{0,N}?` context, including one inside a leading (?i:."""
    stripped = False
    for _ in range(2):                               # outer copy, then the one inside (?i:
        m = _LEADING_CONTEXT.match(rx)
        if not m:
            break
        rx = (m.group(1) or '') + rx[m.end():]       # keep the (?i: opener, drop only the context
        stripped = True
    return rx, stripped

text = open(SRC).read()
blocks = text.split('[[rules]]')[1:]
rules, skipped, ignored_groups, trimmed, posix = [], [], [], [], []
for b in blocks:
    mid = re.search(r'^\s*id\s*=\s*"([^"]+)"', b, re.M)
    mrx = re.search(r"^\s*regex\s*=\s*'''(.*?)'''", b, re.M)
    if not (mid and mrx):
        continue
    rid, rx = mid.group(1), mrx.group(1)
    # normalize Go-regex quirks -> Python re
    rx = rx.replace(r'\z', r'\Z')                    # Go end-of-text -> Python
    rx, classes = translate_posix_classes(rx)        # [[:alnum:]] -> [A-Za-z0-9]
    if classes:
        posix.append((rid, sorted(classes)))
    ignorecase = '(?i)' in rx
    if ignorecase:
        rx = rx.replace('(?i)', '')                  # inline global flag mid-pattern errors on py3.11+
    rx, stripped = strip_leading_context(rx)
    if stripped:
        trimmed.append(rid)
    flags = re.I if ignorecase else 0
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("error")           # treat Future/Deprecation warnings as skip
            re.compile(rx, flags)
    except (re.error, Warning) as e:
        skipped.append((rid, str(e)))
        continue
    mkw = re.search(r'^\s*keywords\s*=\s*\[(.*?)\]', b, re.M | re.S)
    kws = re.findall(r'"([^"]*)"', mkw.group(1)) if mkw else []
    ment = re.search(r'^\s*entropy\s*=\s*([\d.]+)', b, re.M)
    ent = float(ment.group(1)) if ment else None
    # gitleaks' `secretGroup = N` says "the value is group N, not the whole match". It is the
    # vendor's own answer to which group holds the credential, so it outranks our heuristic.
    msg = re.search(r'^\s*secretGroup\s*=\s*(\d+)', b, re.M)
    sg = int(msg.group(1)) if msg else None
    if sg is not None and not 0 <= sg <= re.compile(rx, flags).groups:
        ignored_groups.append((rid, sg))   # declaration cannot apply to this compiled pattern
        sg = None
    # The tier describes the value, so it has to be classified against the group the value is
    # actually taken from -- the declared secretGroup where gitleaks gives one. Classifying the
    # whole pattern instead reads sonar-api-token's keyword `sonar` as a pinned vendor prefix.
    group = sg if sg is not None else secret_group(rx)
    rules.append({"id": rid, "env": env_name(rid), "regex": rx, "keywords": kws,
                  "entropy": ent, "ignorecase": ignorecase,
                  "confidence": classify(rx, group), "secret_group": sg,
                  "group": group})

# Atomically: `open(OUT, "w")` truncates to 0 bytes before json.dump writes anything, so an
# interrupted refresh would leave the shipped ruleset empty and silently disable detection.
with open(OUT + ".tmp", "w") as f:
    json.dump(rules, f, indent=1)   # pure JSON data, loaded at runtime by detect.py
os.replace(OUT + ".tmp", OUT)

print(f"wrote {len(rules)} rules to {OUT}")
declared = sum(1 for r in rules if r["secret_group"] is not None)
print(f"honoured {declared} declared secretGroup(s); derived the rest")
print(f"stripped redundant leading context from {len(trimmed)} regexes")
print(f"translated POSIX character classes in {len(posix)} regexes")
for rid, classes in posix:
    print(f"  ~ {rid}: {' '.join(classes)}")
print(f"skipped {len(skipped)} incompatible regexes")
for rid, err in skipped[:8]:
    print(f"  - {rid}: {err}")
for rid, sg in ignored_groups:
    print(f"  ! {rid}: ignored out-of-range secretGroup {sg}")
