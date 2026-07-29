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
_REFUSAL = "clowk will not modify it -- fix or move the file, then retry."


class VaultUnreadable(Exception):
    """The vault file exists but cannot be understood, so clowk must not write over it.

    Deliberately not a ValueError: cli.cmd_allow and cmd_install already catch ValueError for
    unrelated reasons and would swallow this.
    """


def path():
    return os.environ.get("CLOWK_VAULT", DEFAULT_PATH)


def _now():
    return datetime.datetime.now().isoformat(timespec="seconds")


def _empty():
    return {"version": 1, "secrets": {}}


def _load():
    """The vault as a dict, or raise VaultUnreadable rather than let a write destroy it.

    Three states, not two. "Absent or blank" is an empty vault -- that is first run, and writing
    is correct. "Present but unparseable" is NOT: every mutator loads then saves, so reading it
    as empty made the next capture overwrite every credential the user had while reporting
    success, with no backup. The vault is a plaintext file the README invites you to read and
    hand-edit, so one stray comma is an ordinary accident, and the file is the only copy.
    Same posture as install.py on an unparseable settings.json: refuse, do not guess.
    """
    p = path()
    try:
        with open(p) as f:
            text = f.read()
    except FileNotFoundError:
        return _empty()  # first run
    except UnicodeDecodeError as exc:
        raise VaultUnreadable("%s is not %s text. %s" % (p, exc.encoding, _REFUSAL))
    except (IOError, OSError) as exc:
        # It exists but cannot be read (permissions, a directory, an I/O error). A file we
        # cannot read can still be replaced, so refusing is the only safe answer.
        raise VaultUnreadable("%s could not be read (%s). %s" % (p, exc, _REFUSAL))
    if not text.strip():
        return _empty()  # a zero-byte file holds nothing to lose
    try:
        data = json.loads(text)
    except ValueError:
        raise VaultUnreadable("%s is not valid JSON. %s" % (p, _REFUSAL))
    if not isinstance(data, dict):
        raise VaultUnreadable("%s does not contain a JSON object. %s" % (p, _REFUSAL))
    secrets = data.get("secrets")
    if secrets is None:
        data["secrets"] = {}  # an object with no secrets yet: nothing to lose either
    elif not isinstance(secrets, dict):
        raise VaultUnreadable("%s has a 'secrets' key that is not an object. %s" % (p, _REFUSAL))
    return data


def _save(data):
    # No "is the file still parseable?" check here: every caller goes through _load first, so an
    # unreadable vault has already refused by the time we get here. A re-read would only add I/O.
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


def replace(name, value):
    """Swap a new value in under an existing name, keeping its ledger. False if name is unknown.

    A rotation is not a fresh capture. `store` would suffix the name because the value changed,
    and clearing first then storing would drop first_caught, rule and sources -- the history
    that says what the rotation has to touch.
    """
    data = _load()
    entry = data["secrets"].get(name)
    if entry is None:
        return False
    entry["value"] = value
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
