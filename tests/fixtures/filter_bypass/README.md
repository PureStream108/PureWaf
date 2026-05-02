# Filter Bypass Fixtures

These PHP fixtures model common CTF filter shapes used by PureWaf tests. They are intentionally small single-file examples so `AUTO` and payload-generation behavior can be validated without adding an HTTP exploitation loop.

The fixtures are not copied from Commix. They localize reusable scenario types: blocked whitespace, blocked slash, command blacklist, upload wrapper filtering, fixed command prefixes, and sanitizer-aware command execution.
