# Security policy

## Reporting a vulnerability

Report privately through GitHub's advisory form:
**[Report a vulnerability](https://github.com/Aniumbott/clowk/security/advisories/new)**.

Please do not open a public issue for anything you believe is exploitable, and **never paste a real
credential** into a report — a fake of the same shape reproduces the same behaviour.

Useful things to include: your host and its version, your Python version, the input in fake form,
what you expected, what happened, and `clowk debug-payload` output if it looks host-specific.

## Read this before reporting

clowk is **explicitly not a security boundary**, and the README says so at length. The following are
documented design limits rather than vulnerabilities:

- **`cat` can read the vault.** clowk runs as the same OS user as your agent, so anything clowk can
  read, any other process running as you can read. The vault is plaintext on purpose: encryption
  cannot help when the key would have to be reachable by that same user, and therefore by the agent.
- **Hooks fail open.** Every supported host transmits the prompt if the hook crashes or times out.
  clowk raises the bar; it cannot guarantee interception.
- **The host records the prompt it blocked.** Claude Code writes the blocked prompt to
  `~/.claude/projects/*.jsonl` and prints it to your terminal underneath clowk's message. That is the
  host's behaviour, not clowk's, and it is why a blocked paste should still be rotated.
- **Detection is incomplete.** A credential in a shape no rule matches passes through. The
  Limitations table in the README lists the known gaps with measurements.

What *would* be a vulnerability, and is worth reporting:

- A credential value reaching stdout, stderr, or the rewritten prompt when clowk reported a
  successful block.
- The tool-deny hook being bypassed by a command shape it should refuse.
- `clowk get` being coaxed into printing a value outside command substitution.
- Anything that makes a hook report success while scanning nothing.
- Privilege or path issues in `install` / `setup`: writing outside the documented locations,
  following a symlink out of them, or destroying a settings file it did not write.

## Supported versions

The latest release on PyPI, and `main`. There are no backports.
