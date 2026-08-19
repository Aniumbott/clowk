"""clowk -- catches credentials you paste into an agent chat before they reach the model.

This file is the one place the version is written. pyproject.toml reads it, and a test pins
.claude-plugin/plugin.json and the architecture diagram to it, because a version that disagrees with
itself across three files is how a plugin cache serves a stale snapshot while looking current.
"""
__version__ = "0.2.0"
