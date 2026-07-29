"""Register and unregister clowk's hooks, per host.

Hooks declared in a Claude Code plugin manifest do not fire in build 2.1.202 -- they load and
are counted, but never execute. Only settings-registered hooks run. clowk therefore ships NO
manifest hooks at all and this module is the single registration path, which also makes
double-registration impossible.

Merges into whatever is already there. A real user's settings.json commonly already has hooks
on these same events, so replacing an event array would silently break their setup. Backs up
first, refuses rather than guesses on an unparseable file, and writes atomically.
"""
import json
import os
import shutil

TARGETS = {
    "claude-code": {
        "settings": os.path.join("~", ".claude", "settings.json"),
        "prompt_event": "UserPromptSubmit",
        "tool_event": "PreToolUse",
        "tool_matcher": "Bash|Read",
    },
    "codex": {
        "settings": os.path.join("~", ".codex", "hooks.json"),
        "prompt_event": "UserPromptSubmit",
        "tool_event": "PreToolUse",
        "tool_matcher": "Bash",
    },
    "gemini-cli": {
        "settings": os.path.join("~", ".gemini", "settings.json"),
        "prompt_event": "BeforeAgent",
        "tool_event": "BeforeTool",
        "tool_matcher": None,
    },
}

MARKER = "clowk"


def settings_path(host):
    return os.path.expanduser(TARGETS[host]["settings"])


def is_clowk_entry(entry):
    """True if this hook entry is one of ours -- used by uninstall to remove only our own."""
    if not isinstance(entry, dict):
        return False
    command = entry.get("command")
    return isinstance(command, str) and MARKER in command and (
        "hook_prompt.py" in command or "hook_pretool.py" in command)


def _command(root, script, host):
    return 'python3 "%s" --host %s' % (os.path.join(root, "clowk", script), host)


def _load(path):
    if not os.path.exists(path):
        return {}, False
    with open(path) as f:
        text = f.read()
    if not text.strip():
        return {}, True
    try:
        data = json.loads(text)
    except ValueError:
        raise ValueError(
            "%s is not valid JSON. clowk will not modify it -- fix or move the file, then retry." % path)
    if not isinstance(data, dict):
        raise ValueError("%s does not contain a JSON object. clowk will not modify it." % path)
    return data, True


def _save(path, data):
    parent = os.path.dirname(path)
    if parent and not os.path.isdir(parent):
        os.makedirs(parent)
    tmp = path + ".tmp"
    with open(tmp, "w") as f:
        json.dump(data, f, indent=2)
    os.replace(tmp, path)


def _backup(path):
    if not os.path.exists(path):
        return None
    for n in range(1, 100):
        candidate = "%s.clowk-backup-%d" % (path, n)
        if not os.path.exists(candidate):
            shutil.copy2(path, candidate)
            return candidate
    return None


def _add(hooks, event, matcher, command, path):
    """Append our entry to `event`, reusing a group with the same matcher. Returns 1 if added."""
    groups = hooks.setdefault(event, [])
    if not isinstance(groups, list):
        # Overwriting it would silently delete whatever the user had on this event while
        # reporting success. Refuse, like the unparseable-file and non-object-hooks cases.
        raise ValueError(
            "%s has a %r hook entry that is not an array. clowk will not modify it -- "
            "fix or move the file, then retry." % (path, event))
    for group in groups:
        if not isinstance(group, dict):
            continue
        for entry in group.get("hooks", []):
            if isinstance(entry, dict) and entry.get("command") == command:
                return 0  # already registered -- idempotent
    entry = {"type": "command", "command": command}
    for group in groups:
        if isinstance(group, dict) and group.get("matcher") == matcher:
            group.setdefault("hooks", []).append(entry)
            return 1
    group = {"hooks": [entry]}
    if matcher:
        group["matcher"] = matcher
    groups.append(group)
    return 1


def install(host, root, settings_path_override=None):
    target = TARGETS[host]  # KeyError for an unknown host is the intended behaviour
    path = settings_path_override or settings_path(host)
    data, existed = _load(path)
    backup = _backup(path) if existed else None

    hooks = data.setdefault("hooks", {})
    if not isinstance(hooks, dict):
        raise ValueError("%s has a 'hooks' key that is not an object. clowk will not modify it." % path)

    added = _add(hooks, target["prompt_event"], None, _command(root, "hook_prompt.py", host), path)
    added += _add(hooks, target["tool_event"], target["tool_matcher"],
                  _command(root, "hook_pretool.py", host), path)

    _save(path, data)
    return {"settings": path, "backup": backup, "added": added}


def uninstall(host, settings_path_override=None):
    target = TARGETS[host]
    path = settings_path_override or settings_path(host)
    data, existed = _load(path)
    if not existed:
        return {"settings": path, "removed": 0}

    hooks = data.get("hooks")
    if not isinstance(hooks, dict):
        return {"settings": path, "removed": 0}

    removed = 0
    for event in (target["prompt_event"], target["tool_event"]):
        groups = hooks.get(event)
        if not isinstance(groups, list):
            continue
        kept_groups = []
        for group in groups:
            if not isinstance(group, dict):
                kept_groups.append(group)
                continue
            entries = group.get("hooks", [])
            kept = [e for e in entries if not is_clowk_entry(e)]
            removed += len(entries) - len(kept)
            group["hooks"] = kept
            if kept:
                kept_groups.append(group)
        if kept_groups:
            hooks[event] = kept_groups
        else:
            hooks.pop(event, None)

    if removed:
        _save(path, data)
    return {"settings": path, "removed": removed}
