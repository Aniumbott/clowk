#!/usr/bin/env python3
"""clowk management CLI. Backs the /clowk slash command.
Usage:
  clowk list                         show stored secrets (+ whether each is sandbox-masked)
  clowk clear <NAME>                 remove a stored secret
  clowk rename <OLD> <NEW>           rename a stored secret
  clowk mask <NAME> [host ...]       Layer B: make <NAME> unreadable by the agent (sandbox masking).
                                     Hosts default to a known set for the secret type if omitted.
  clowk unmask <NAME>                stop masking <NAME>"""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from clowk import store, sandbox

def cmd_list():
    items = store.list_secrets()
    if not items:
        print("No secrets stored.")
        return
    masked = sandbox.masked_names()
    print(f"{len(items)} secret(s) stored (values in settings.local.json, hidden here):\n")
    for name, meta in items.items():
        tag = "  [MASKED — agent cannot read]" if name in masked else ""
        print(f"  {name}{tag}")
        print(f"    caught: {meta['caught']}")
        if meta["sources"]:
            print(f"    from:   {', '.join(meta['sources'])}")
        print(f"    used by: {', '.join(meta['uses']) if meta['uses'] else '(not seen used yet)'}")
    print("\nNote: clearing a secret unsets it for NEW sessions; a running session keeps it until restart.")

def cmd_clear(name):
    print(f"Cleared {name}." if store.clear(name) else f"No secret named {name}.")

def cmd_rename(old, new):
    print(f"Renamed {old} -> {new}." if store.rename(old, new) else f"No secret named {old}.")

def cmd_mask(name, hosts):
    if name not in store.values():
        print(f"No secret named {name}. Run `clowk list`.")
        return 1
    hosts = hosts or sandbox.default_hosts(name)
    if not hosts:
        print(f"No default hosts known for {name}. Specify where it's used, e.g.:\n"
              f"  clowk mask {name} api.example.com")
        return 1
    r = sandbox.apply_mask(name, hosts)
    print(f"Masked {name}: the agent can USE it for {', '.join(r['hosts'])} but can no longer READ it.")
    print("Applied to sandbox config: enabled, tlsTerminate, allowedDomains, credentials.mask, "
          "store denyRead" + (", strict (no unsandboxed escape)" if r["strict"] else ""))
    print("\n⚠ This turns ON the Bash sandbox for ALL commands (macOS/Linux/WSL2 only). RESTART Claude Code")
    print("  to apply. After restart, `echo $%s` shows a sentinel, not the real value." % name)
    print("  Caveats: network-only protection to the listed hosts; some tools may need allowedDomains/")
    print("  allowWrite entries; run `clowk unmask %s` to revert." % name)
    return 0

def cmd_unmask(name):
    print(f"Unmasked {name} (restart to apply)." if sandbox.remove_mask(name) else f"{name} was not masked.")

def main(argv):
    if not argv or argv[0] in ("-h", "--help", "help"):
        print(__doc__); return 0
    cmd, args = argv[0], argv[1:]
    if cmd == "list":
        cmd_list()
    elif cmd == "clear" and len(args) == 1:
        cmd_clear(args[0])
    elif cmd == "rename" and len(args) == 2:
        cmd_rename(args[0], args[1])
    elif cmd == "mask" and len(args) >= 1:
        return cmd_mask(args[0], args[1:])
    elif cmd == "unmask" and len(args) == 1:
        cmd_unmask(args[0])
    else:
        print(__doc__); return 1
    return 0

if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
