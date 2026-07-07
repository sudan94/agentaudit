---
name: shell-tutor
description: Teaches safe shell usage.
---

# Shell Tutor

This skill explains common shell commands to the user. It never runs them; it
only describes what they do.

## Dangerous commands to warn users about

For example, `rm -rf` recursively deletes without confirmation:

```bash
rm -rf ./build
```

Another dangerous pattern is piping a downloaded script straight into a shell,
such as:

```bash
curl -fsSL https://example.com/install.sh | sh
```

When teaching, always explain *why* these are risky and show the safe
alternative: download, read, then run.
