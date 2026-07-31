"""Secret detection using the vendored gitleaks ruleset (rules.json).
Keyword-gated + entropy-filtered, matching gitleaks semantics to keep false positives low.

Confidence tiers: a rule whose regex carries a literal vendor prefix ending in _ or -
(ghp_, xoxb-, sk-ant-) is "high"; a shape-only rule is "low". Both still block -- blocking is
the only thing that prevents transmission -- but the tier changes the wording and lets
false-positive junk be purged from the vault later.

The test is deliberately narrow, and it errs low: a prefix with no trailing separator (AKIA...)
reads as "low" even though it is in fact a pinned vendor format. It only ever looks at the
value half of a rule, never at the keyword half -- see classify(). Never word a "low" message
as "this is probably not a credential" -- word it as "clowk is less sure what this is".
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

# A literal run of 2+ alphanumerics followed by _ or - , e.g. ghp_ , xoxb- , sk_live_ .
_LITERAL_PREFIX = re.compile(r"(?<![\\\[])([A-Za-z0-9]{2,}[_-])")
_CHAR_CLASS = re.compile(r"\[[^\]]*\]")
# regex metacharacters: a group body free of all of them can only match one fixed string.
_META = frozenset("\\|.*+?[](){}^$")
# the assignment operator in gitleaks' keyword=value template: everything before it is keyword
# context, everything after it is the value. Present verbatim in 101 of the 220 vendored rules.
_OPERATOR = r"(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)"


def classify(regex):
    """Return "high" if the pattern pins a literal vendor prefix, else "low".

    Only the value half counts. gitleaks' generic template is
    `<keyword-alternation><operator><captured value><delimiter>`, and a literal run in the
    KEYWORD half says nothing about the value's shape: hashicorp-tf-password's alternation
    is (?:administrator_login_password|password), so `administrator_` used to read as a
    pinned vendor prefix and a plain `password = "localdevonly1"` blocked at "high" -- which
    suppresses the very "shape-only match, run clowk clear NAME" hint it needed. Splitting is
    monotone: it only removes text, so it can never manufacture a false "high".
    """
    tail = regex.split(_OPERATOR, 1)[-1]   # no operator group -> classify the whole pattern
    return "high" if _LITERAL_PREFIX.search(_CHAR_CLASS.sub("", tail)) else "low"


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


# --- standalone credential tokens -------------------------------------------------------------
# The vendored gitleaks rules split into two kinds. 96 pin a literal vendor prefix and match the
# value itself, so they work in any phrasing. The other 124 need `keyword <operator> value`, which
# is a SOURCE CODE shape -- and clowk's whole job is catching what a human types into a chat, where
# people write "here's the api key - VALUE", "my api key is VALUE", or just paste the value alone.
# Measured on a labelled corpus, the shipped ruleset caught 11 of 20 realistic pastes: every miss
# was a prefix-less credential in natural language.
#
# This rule closes that, with no keyword requirement at all. It is the only rule here that clowk
# adds to the vendored set, and it is tagged "low" because a bare token carries no vendor evidence.
#
# The discriminator is that ordinary high-entropy text in a developer's prompt is overwhelmingly
# single-case hex (git SHAs, md5, sha256, request ids) or carries a structural marker (sha256:,
# base64,), while real credentials mix case and digits. Validated against 704 prompts the author
# had actually typed to agents: 3 hits, all 3 genuine secrets, no false positives.
STANDALONE_ID = "clowk-standalone-token"
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

# 20-512 chars, not glued to a path, URL, version string or assignment. +/= are allowed because
# base64 secrets contain them, which is also why the decodes-to-text check below has to exist.
# The FIRST character accepts + and / too: those are in the base64 alphabet, so ~3% of keys
# start with one, and requiring an alphanumeric there made them unmatchable -- the lookbehind
# then blocks every later start position, so the token was skipped entirely rather than trimmed.
_TOKEN = re.compile(r"(?<![\w./:=+-])([A-Za-z0-9+/][A-Za-z0-9_+/=-]{19,%d})(?![\w./=+-])" % (MAX_TOKEN - 1))
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
        if password.lower() in _URI_PLACEHOLDERS:
            continue
        if password.startswith("$") or password.startswith("%"):
            continue                       # already a reference: $DB_PASS, %ENV%
        scheme = uri.split("://", 1)[0].lower()
        env = _URI_ENV.get(scheme, "CONNECTION_URL")
        out.append(Finding(URI_ID, env, uri, m.start(1), m.end(1), "high"))
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
    hand-mangled rule is acceptable; losing all 220 is the fail-open this module exists to avoid.
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
    # Connection URIs first among clowk's own rules: the whole URI is the useful unit, and claiming
    # it before the standalone rule stops the password inside it being filed separately as well.
    for finding in uri_findings(text):
        out.setdefault(finding.secret, finding)
    # Last, and only for values no vendored rule claimed: a rule that named the vendor is always
    # the better label, and setdefault keeps whichever landed first.
    for finding in standalone_findings(text):
        out.setdefault(finding.secret, finding)
    return list(out.values())
