"""Central, global storage + rotation ledger for clowk.
- Values live in ~/.claude/settings.local.json `env` (the file Claude Code reads to resolve $VAR).
- Metadata (when caught, where, what used it) lives in ~/.clowk/ledger.json.
Both are user-level and single; nothing is per-project (a project .claude/ could hit git)."""
import os, json, datetime

HOME = os.path.expanduser("~")
SETTINGS = os.environ.get("CLOWK_SETTINGS", os.path.join(HOME, ".claude", "settings.local.json"))
LEDGER = os.environ.get("CLOWK_LEDGER", os.path.join(HOME, ".clowk", "ledger.json"))

def _load(path, default):
    try:
        with open(path) as f:
            return json.load(f)
    except (FileNotFoundError, ValueError):
        return default

def _save(path, data):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w") as f:
        json.dump(data, f, indent=2)
    os.replace(tmp, path)   # atomic; never leaves a half-written secrets file

def _now():
    return datetime.datetime.now().isoformat(timespec="seconds")

def store(env_name, value, source=""):
    """Write the secret into settings env (with collision suffixing) + ledger. Returns the final key."""
    settings = _load(SETTINGS, {})
    env = settings.setdefault("env", {})
    key, n = env_name, 2
    while key in env and env[key] != value:   # same name, different value -> suffix, don't clobber
        key = f"{env_name}_{n}"; n += 1
    env[key] = value
    _save(SETTINGS, settings)

    ledger = _load(LEDGER, {"secrets": {}})
    entry = ledger["secrets"].get(key, {"first_caught": _now(), "sources": [], "uses": []})
    if source and source not in entry["sources"]:
        entry["sources"].append(source)
    ledger["secrets"][key] = entry
    _save(LEDGER, ledger)
    return key

def record_use(key, where):
    ledger = _load(LEDGER, {"secrets": {}})
    e = ledger["secrets"].get(key)
    if e is not None and where not in e["uses"]:
        e["uses"].append(where)
        _save(LEDGER, ledger)

def values():
    """All stored {key: value} for output redaction / usage scanning."""
    return _load(SETTINGS, {}).get("env", {})

def list_secrets():
    env = _load(SETTINGS, {}).get("env", {})
    led = _load(LEDGER, {"secrets": {}})["secrets"]
    return {k: {"caught": led.get(k, {}).get("first_caught", "?"),
                "sources": led.get(k, {}).get("sources", []),
                "uses": led.get(k, {}).get("uses", [])} for k in env}

def clear(key):
    settings = _load(SETTINGS, {})
    removed = settings.get("env", {}).pop(key, None) is not None
    if removed:
        _save(SETTINGS, settings)
    ledger = _load(LEDGER, {"secrets": {}})
    if ledger["secrets"].pop(key, None) is not None:
        _save(LEDGER, ledger)
    return removed

def rename(old, new):
    settings = _load(SETTINGS, {})
    env = settings.get("env", {})
    if old not in env:
        return False
    env[new] = env.pop(old)
    _save(SETTINGS, settings)
    ledger = _load(LEDGER, {"secrets": {}})
    if old in ledger["secrets"]:
        ledger["secrets"][new] = ledger["secrets"].pop(old)
        _save(LEDGER, ledger)
    return True
