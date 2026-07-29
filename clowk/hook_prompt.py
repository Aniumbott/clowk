#!/usr/bin/env python3
"""clowk pre-transmit prompt hook: detect a pasted credential -> file it -> block the turn.

This is the only part of clowk that prevents a leak. It runs locally, before the prompt is
transmitted, on Claude Code (UserPromptSubmit), Codex (UserPromptSubmit) and Gemini CLI
(BeforeAgent).

No host can rewrite a submitted prompt, so the flow is block-and-repaste, with the rewrite
placed on the clipboard.

EVERY HOST FAILS OPEN: if this script crashes or times out, the secret is transmitted. Hence
stdlib only, no network, and a bare except around the whole body.

Bypass: start the message with `unclowk` to send it raw.
"""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from clowk import clip, hosts, vault
from clowk.detect import scan

BYPASS = "unclowk"


def _host_from(argv):
    for i, arg in enumerate(argv):
        if arg == "--host" and i + 1 < len(argv):
            return argv[i + 1]
        if arg.startswith("--host="):
            return arg.split("=", 1)[1]
    return "claude-code"


def build_message(rewritten, stored, tiers, copied):
    """The block reason. Plain text: hooks cannot set colour or markdown."""
    lines = ["clowk stopped a credential before it reached the model."]
    for name in stored:
        tier = tiers.get(name, "")
        note = "  (shape-only match -- if this is a false positive, run: clowk clear %s)" % name if tier == "low" else ""
        lines.append("  stored as $%s%s" % (name, note))
    lines.append("")
    lines.append("Your prompt, rewritten%s:" % (" -- already on your clipboard" if copied else ""))
    lines.append("")
    lines.append("    " + rewritten)
    lines.append("")
    lines.append("To send the original text instead, start your message with:  %s" % BYPASS)
    return "\n".join(lines)


def main(argv, stdin, stdout, stderr):
    host = _host_from(argv)
    try:
        payload = json.load(stdin)
    except ValueError:
        return 0  # unparseable input: never block on our own confusion

    event = hosts.read_event(payload)
    prompt = event["prompt"]
    if not prompt or prompt.lstrip().lower().startswith(BYPASS):
        return 0

    findings = scan(prompt)
    if not findings:
        return 0  # nothing detected -> pass through untouched

    rewritten, stored, tiers = prompt, [], {}
    # Longest secret first, and skip anything a longer match already swallowed. Rules do nest:
    # flutterwave-encryption-key's pattern is a prefix of flutterwave-secret-key's, so one
    # pasted key yields two findings. Replacing the short one first would leave the tail of the
    # real value in the rewrite -- which is what goes on the clipboard and gets repasted.
    for finding in sorted(findings, key=lambda f: len(f.secret), reverse=True):
        if finding.secret not in rewritten:
            continue
        name = vault.store(
            finding.env, finding.secret,
            rule=finding.rule_id, confidence=finding.confidence, source=event["cwd"],
        )
        rewritten = rewritten.replace(finding.secret, "$" + name)
        stored.append(name)
        tiers[name] = finding.confidence

    copied = clip.copy(rewritten)
    return hosts.block(host, build_message(rewritten, stored, tiers, copied), stdout, stderr)


if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv[1:], sys.stdin, sys.stdout, sys.stderr))
    except Exception:  # noqa: BLE001 -- every host fails open; never let a traceback block a turn
        sys.exit(0)
