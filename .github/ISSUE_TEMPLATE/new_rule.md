---
name: New detection rule
about: Propose a new attack pattern for skillcheck to catch
title: "[rule] "
labels: new-rule
---

**The attack**
Describe the malicious pattern in agent instructions this rule should catch.

**Proposed rule**

```yaml
- id: SC-XXX-000
  title:
  severity: high | medium | low | info
  category: hidden-content | injection | exfiltration | command | mcp | obfuscation
  applies_to: [markdown]
  patterns:
    - regex: ''
  examples:
    match: ""
    no_match: ""
```

**Real-world example (optional)**
A link or excerpt (responsibly redacted) where you saw this in the wild.

**False-positive risk**
What benign text might look similar, and how the `no_match` example guards it.
