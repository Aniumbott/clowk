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

text = open(SRC).read()
blocks = text.split('[[rules]]')[1:]
rules, skipped, ignored_groups = [], [], []
for b in blocks:
    mid = re.search(r'^\s*id\s*=\s*"([^"]+)"', b, re.M)
    mrx = re.search(r"^\s*regex\s*=\s*'''(.*?)'''", b, re.M)
    if not (mid and mrx):
        continue
    rid, rx = mid.group(1), mrx.group(1)
    # normalize Go-regex quirks -> Python re
    rx = rx.replace(r'\z', r'\Z')                    # Go end-of-text -> Python
    ignorecase = '(?i)' in rx
    if ignorecase:
        rx = rx.replace('(?i)', '')                  # inline global flag mid-pattern errors on py3.11+
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
    rules.append({"id": rid, "env": env_name(rid), "regex": rx, "keywords": kws,
                  "entropy": ent, "ignorecase": ignorecase,
                  "confidence": classify(rx), "secret_group": sg,
                  "group": sg if sg is not None else secret_group(rx)})

with open(OUT, "w") as f:
    json.dump(rules, f, indent=1)   # pure JSON data, loaded at runtime by detect.py

print(f"wrote {len(rules)} rules to {OUT}")
declared = sum(1 for r in rules if r["secret_group"] is not None)
print(f"honoured {declared} declared secretGroup(s); derived the rest")
print(f"skipped {len(skipped)} incompatible regexes")
for rid, err in skipped[:8]:
    print(f"  - {rid}: {err}")
for rid, sg in ignored_groups:
    print(f"  ! {rid}: ignored out-of-range secretGroup {sg}")
