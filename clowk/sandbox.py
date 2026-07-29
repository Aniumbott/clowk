"""Layer B: configure Claude Code's sandbox credential masking so a stored secret is UNREADABLE by the
agent but still usable for network calls. Writes to user settings (~/.claude/settings.json) — mask entries
are only honored from user/managed/CLI settings, never project settings.

What masking does (per Claude Code docs): inside the sandbox the env var holds a per-session SENTINEL, so
`echo $VAR` shows garbage; the real value is swapped in by the proxy only for requests to `injectHosts`.
Requires: sandbox enabled, network.tlsTerminate (experimental) for the injection, and injectHosts within
allowedDomains. macOS/Linux/WSL2 only (not native Windows). For a hard guarantee we also set strict mode
(no unsandboxed escape hatch) and deny reads of the value store file."""
import os, json
from clowk.store import SETTINGS as VALUE_STORE   # ~/.claude/settings.local.json (holds real values)

USER_SETTINGS = os.environ.get("CLOWK_USER_SETTINGS", os.path.expanduser("~/.claude/settings.json"))

# stored env name -> sensible default hosts the secret authenticates to
HOST_MAP = {
    "GITHUB_TOKEN": ["api.github.com", "github.com"], "GITHUB_OAUTH_TOKEN": ["api.github.com", "github.com"],
    "GITHUB_APP_TOKEN": ["api.github.com"], "GITLAB_TOKEN": ["gitlab.com"],
    "OPENAI_API_KEY": ["api.openai.com"], "ANTHROPIC_API_KEY": ["api.anthropic.com"],
    "STRIPE_SECRET_KEY": ["api.stripe.com"], "SLACK_BOT_TOKEN": ["slack.com", "api.slack.com"],
    "SLACK_USER_TOKEN": ["slack.com", "api.slack.com"], "SENDGRID_API_KEY": ["api.sendgrid.com"],
    "TWILIO_API_KEY": ["api.twilio.com"], "MAILGUN_API_KEY": ["api.mailgun.net"],
    "NPM_TOKEN": ["registry.npmjs.org"], "DIGITALOCEAN_TOKEN": ["api.digitalocean.com"],
}

def default_hosts(name):
    return HOST_MAP.get(name, [])

def _load():
    try:
        with open(USER_SETTINGS) as f:
            return json.load(f)
    except (FileNotFoundError, ValueError):
        return {}

def _save(data):
    os.makedirs(os.path.dirname(USER_SETTINGS), exist_ok=True)
    tmp = USER_SETTINGS + ".tmp"
    with open(tmp, "w") as f:
        json.dump(data, f, indent=2)
    os.replace(tmp, USER_SETTINGS)

def _dedup_append(lst, item):
    if item not in lst:
        lst.append(item)

def apply_mask(name, hosts, strict=True):
    s = _load()
    sb = s.setdefault("sandbox", {})
    sb["enabled"] = True
    if strict:
        sb["allowUnsandboxedCommands"] = False        # close the escape hatch that could read the real value
    net = sb.setdefault("network", {})
    net.setdefault("tlsTerminate", {})                # required so the proxy can inject the real value
    dom = net.setdefault("allowedDomains", [])
    for h in hosts:
        _dedup_append(dom, h)                          # injectHosts must be within allowedDomains
    creds = sb.setdefault("credentials", {})
    envs = creds.setdefault("envVars", [])
    envs[:] = [e for e in envs if e.get("name") != name]   # replace any existing entry
    envs.append({"name": name, "mode": "mask", "injectHosts": list(hosts)})
    files = creds.setdefault("files", [])
    if not any(f.get("path") == VALUE_STORE for f in files):
        files.append({"path": VALUE_STORE, "mode": "deny"})   # sandboxed `cat` can't read the value store
    _save(s)
    return {"name": name, "hosts": list(hosts), "strict": strict, "settings": USER_SETTINGS}

def remove_mask(name):
    s = _load()
    envs = s.get("sandbox", {}).get("credentials", {}).get("envVars", [])
    before = len(envs)
    envs[:] = [e for e in envs if e.get("name") != name]
    if len(envs) != before:
        _save(s)
        return True
    return False

def masked_names():
    envs = _load().get("sandbox", {}).get("credentials", {}).get("envVars", [])
    return {e["name"] for e in envs if e.get("mode") == "mask"}
