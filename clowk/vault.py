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
_META_KEYS = ("rule", "confidence", "first_caught", "last_caught", "catches", "sources", "uses")
_REFUSAL = "clowk will not modify it -- fix or move the file, then retry."


def _default(key):
    """What a metadata key reads as when the vault predates it.

    A vault written by an earlier clowk has no `catches` and no `last_caught`, and every read path
    has to survive that -- the same treatment `sources` and `uses` already get. A function rather
    than a dict of defaults so each caller gets its OWN empty list; one shared list handed to every
    entry is a mutation bug waiting for its first caller.
    """
    if key in ("sources", "uses"):
        return []
    return 0 if key == "catches" else ""


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
        # encoding="utf-8", not the locale codec: clowk's own writes are pure ASCII, but a
        # hand-edited source path is not, and a cp1252 read would mojibake it and write that back.
        with open(p, encoding="utf-8") as f:
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
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)  # ensure_ascii on, so the file stays ASCII-only either way
    try:
        os.chmod(tmp, 0o600)  # no-op on Windows; NTFS relies on user-profile ACLs
    except OSError:
        pass
    os.replace(tmp, p)


def store(name, value, rule="", confidence="", source="", detail=False):
    """Write value under name and return the final key. Suffixes on a same-name/different-value clash.

    With `detail`, returns (key, rotated) instead, where `rotated` is `name` when the clash was
    with an entry recorded under the SAME rule -- i.e. almost certainly the same credential after
    a rotation -- and "" otherwise. The caller cannot work that out from the key alone, which is
    why a rotation used to pass in silence: the new value lands under NAME_2 while the plain NAME
    still resolves to the revoked one, and nothing said so at the moment it could be acted on.

    Reported, never acted on. Promoting the new value to the plain name would silently change what
    an existing $NAME means for anyone who already scripted against it, which is the same class of
    bug in the other direction. `replace` exists for when the user decides that is what they want.

    Same rule id, not same name: two vendors' credentials can land on one env name -- GENERIC_API_KEY
    especially -- and that is a name collision, about which "did you rotate it?" is the wrong
    question. An entry with no rule recorded (anything `clowk add` stored, or a hand-edited one)
    reports nothing either, because there is nothing to compare.

    EVERY call adds to the ledger -- `catches` and `last_caught` -- whatever the directory dedup
    below decides. Re-catching the same credential where clowk had already seen it used to record
    nothing at all: `sources` was the only running total and it appends only for a NEW directory, so
    the second and the twentieth paste of one key in one project were both invisible. That left
    clowk unable to answer the one question its own ledger exists for -- is this becoming a habit? --
    which is the signal that says stop pasting it and reference it instead.

    Costs nothing extra per capture, which matters because hook_prompt files up to MAX_FILED values
    per paste and every one of them reloads and rewrites this whole file: `_save` was ALREADY
    unconditional here, dedup or not, so this adds two dict writes and two JSON keys per entry and
    no I/O whatsoever.
    """
    data = _load()
    secrets = data["secrets"]
    rotated = ""
    existing = secrets.get(name)
    if existing and existing.get("value") != value and rule and existing.get("rule") == rule:
        rotated = name
    key, n = name, 2
    while key in secrets and secrets[key].get("value") != value:
        key = "%s_%d" % (name, n)
        n += 1
    now = _now()
    known = secrets.get(key)          # None means this call creates the entry
    entry = known or {"first_caught": now, "sources": [], "uses": []}
    entry["value"] = value
    if rule:
        entry["rule"] = rule
    if confidence:
        entry["confidence"] = confidence
    entry["catches"] = _prior_catches(entry, known is not None) + 1
    entry["last_caught"] = now
    sources = entry.setdefault("sources", [])
    if source and source not in sources:
        sources.append(source)
    secrets[key] = entry
    _save(data)
    return (key, rotated) if detail else key


def _prior_catches(entry, already_known):
    """How many catches this entry had before the one being recorded now.

    An entry that predates the field resumes from 1 rather than from 0, because its `first_caught`
    is proof that a catch happened -- counting it as the first would misreport an upgraded vault
    from the moment of upgrade. A brand-new entry resumes from 0.

    The vault is a plaintext file the README invites you to hand-edit, so a count that is a string,
    a list, a bool or negative has to fall back rather than raise: a capture that fails here is a
    credential clowk does not file, and it is being asked to file it.
    """
    prior = entry.get("catches")
    if isinstance(prior, int) and not isinstance(prior, bool) and prior >= 0:
        return prior
    return 1 if already_known else 0


def get(name):
    entry = _load()["secrets"].get(name)
    return entry.get("value") if entry else None


def names():
    return sorted(_load()["secrets"].keys())


def list_secrets():
    """Metadata only -- deliberately never returns a value."""
    out = {}
    for name, entry in _load()["secrets"].items():
        out[name] = dict((k, entry.get(k, _default(k))) for k in _META_KEYS)
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

# --- export and purge -----------------------------------------------------------------------------
# The vault is the only copy of anything it holds. `clowk uninstall` used to leave it behind silently,
# which is the wrong kind of quiet in both directions: a user who wanted a clean machine kept a
# plaintext file of live credentials, and a user who assumed uninstall took it with them believed they
# had cleaned up when they had not.

def export_data():
    """The whole vault as a JSON-serialisable dict, values included. None if there is nothing.

    Deliberately the vault's own structure rather than a report: restoring is then a file copy back to
    the path in `path()`, not a re-typing of every credential by hand. A `_restore` key is added
    because JSON cannot carry a comment, and an export nobody knows how to put back is a puzzle
    rather than a backup. Extra top-level keys are ignored by _load, so the copy-back still works.
    """
    data = _load()
    secrets = data.get("secrets") or {}
    if not secrets:
        return None
    out = dict(data)
    out["_restore"] = (
        "Every value below is a live credential in plaintext. To restore, copy this file over %s "
        "(mode 0600), or add them one at a time with `clowk add NAME`. clowk's deny hook does NOT "
        "protect this file -- it only knows the vault's real path -- so move it somewhere safe or "
        "delete it once you are done." % path())
    return out


def write_export(destination):
    """Write export_data() as JSON at mode 0600. Returns the path, or None if there is nothing."""
    data = export_data()
    if data is None:
        return None
    destination = os.path.expanduser(destination)
    parent = os.path.dirname(destination)
    if parent and not os.path.isdir(parent):
        os.makedirs(parent)
    # Created with the restrictive mode rather than chmod-ed after: between the two there is a window
    # in which a file of live credentials is world-readable.
    handle = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        with os.fdopen(handle, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
            f.write("\n")
    except Exception:
        try:
            os.close(handle)
        except OSError:
            pass
        raise
    try:
        os.chmod(destination, 0o600)   # no-op on Windows, which relies on user-profile ACLs
    except OSError:
        pass
    return destination


def purge():
    """Delete the vault file itself. Returns True if it was there. Irreversible."""
    target = path()
    if not os.path.exists(target):
        return False
    os.remove(target)
    return True


def count():
    """How many credentials the vault holds, or 0 if it is absent or empty."""
    try:
        return len((_load().get("secrets") or {}))
    except VaultUnreadable:
        return 0
