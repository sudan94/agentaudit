# Rule reference

This page lists skillcheck's built-in detections. Generate the current list at
any time with:

```bash
skillcheck rules
skillcheck rules --explain SC-INJ-003
```

> An auto-generated, always-current version of this reference is planned for
> v0.2 (`docs autogen`). Until then, `skillcheck rules` is the source of truth.

## Categories

| Category | What it covers |
|---|---|
| `hidden-content` | Content invisible to a human reader: HTML comments, zero-width and bidi unicode, homoglyphs, invisible CSS, script/data URIs. |
| `injection` | Attempts to override instructions, hijack the agent's persona, hide behavior, act silently, script deception, trigger conditionally, or persist into other files. |
| `exfiltration` | Credential/secret paths combined with network egress; known callback endpoints; URL shorteners, raw IPs, punycode. |
| `command` | Dangerous shell commands the agent is told to run: pipe-to-shell, `rm -rf`, reverse shells, base64-to-shell, cron/registry persistence, git-config tampering. |
| `mcp` | MCP server capability combinations, unpinned package execution, inlined secrets, plain-HTTP endpoints, and settings hooks. |
| `obfuscation` | Base64/hex blobs, decoded and re-scanned one level deep. |

## Rule ID scheme

`SC-<CAT>-<NNN>` where `<CAT>` is a short category tag (`INJ`, `HID`, `EXF`,
`CMD`, `MCP`, `OBF`, `AI`) and `<NNN>` is a zero-padded number. Rules numbered
`001–099` are typically YAML rules; analyzer-implemented rules use `100+` or a
category-specific range. `SC-AI-000` marks findings from the `--ai` deep scan.
