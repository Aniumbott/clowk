"""The clowk vault: one file holding captured values and their metadata.

Plaintext at 0600 on purpose. Encryption cannot help here: clowk runs as the same OS user as
the agent, so the key would have to be reachable by that same user. This is the same posture as
~/.aws/credentials, ~/.npmrc and an unencrypted id_rsa -- and a clear improvement on
~/.claude/settings.local.json, which sits in a directory people commit and which every session's
env loads wholesale.
"""
import datetime
import json
import os

DEFAULT_PATH = os.path.join(os.path.expanduser("~"), ".clowk", "vault.json")
_META_KEYS = ("rule", "confidence", "first_caught", "sources", "uses")


def path():
    return os.environ.get("CLOWK_VAULT", DEFAULT_PATH)


def _now():
    return datetime.datetime.now().isoformat(timespec="seconds")


def _load():
    try:
        with open(path()) as f:
            data = json.load(f)
    except (IOError, OSError, ValueError):
        return {"version": 1, "secrets": {}}
    if not isinstance(data, dict) or not isinstance(data.get("secrets"), dict):
        return {"version": 1, "secrets": {}}
    return data


def _save(data):
    p = path()
    parent = os.path.dirname(p)
    if parent:
        try:
            os.makedirs(parent, mode=0o700)
        except OSError:
            pass  # already exists
    tmp = p + ".tmp"
    with open(tmp, "w") as f:
        json.dump(data, f, indent=2)
    try:
        os.chmod(tmp, 0o600)  # no-op on Windows; NTFS relies on user-profile ACLs
    except OSError:
        pass
    os.replace(tmp, p)


def store(name, value, rule="", confidence="", source=""):
    """Write value under name and return the final key. Suffixes on a same-name/different-value clash."""
    data = _load()
    secrets = data["secrets"]
    key, n = name, 2
    while key in secrets and secrets[key].get("value") != value:
        key = "%s_%d" % (name, n)
        n += 1
    entry = secrets.get(key) or {"first_caught": _now(), "sources": [], "uses": []}
    entry["value"] = value
    if rule:
        entry["rule"] = rule
    if confidence:
        entry["confidence"] = confidence
    sources = entry.setdefault("sources", [])
    if source and source not in sources:
        sources.append(source)
    secrets[key] = entry
    _save(data)
    return key


def get(name):
    entry = _load()["secrets"].get(name)
    return entry.get("value") if entry else None


def names():
    return sorted(_load()["secrets"].keys())


def list_secrets():
    """Metadata only -- deliberately never returns a value."""
    out = {}
    for name, entry in _load()["secrets"].items():
        out[name] = dict((k, entry.get(k, [] if k in ("sources", "uses") else "")) for k in _META_KEYS)
    return out


def clear(name):
    data = _load()
    if data["secrets"].pop(name, None) is None:
        return False
    _save(data)
    return True


def rename(old, new):
    data = _load()
    secrets = data["secrets"]
    if old not in secrets or new in secrets:
        return False
    secrets[new] = secrets.pop(old)
    _save(data)
    return True


def record_use(name, where):
    data = _load()
    entry = data["secrets"].get(name)
    if entry is None or not where:
        return
    uses = entry.setdefault("uses", [])
    if where not in uses:
        uses.append(where)
        _save(data)
