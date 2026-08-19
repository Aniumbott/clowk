# clowk-cli

**This is an alias. The real package is [`clowk`](https://pypi.org/project/clowk/).**

It exists so that `clowk-cli` reaches the tool people are looking for instead of an empty name, and
so that nobody else can publish something confusable next to a security tool. It contains no code of
its own — installing it installs `clowk`, which provides the `clowk` command.

Prefer installing the real thing directly:

```bash
uv tool install clowk
pipx install clowk
```

`pip install clowk` is refused on Homebrew, Debian, Ubuntu and Fedora Pythons
([PEP 668](https://peps.python.org/pep-0668/)). Source and documentation:
<https://github.com/Aniumbott/clowk>.
