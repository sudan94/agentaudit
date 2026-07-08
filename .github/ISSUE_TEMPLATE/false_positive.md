---
name: False positive
about: agentaudit flagged something benign
title: "[false-positive] "
labels: false-positive
---

**Rule that fired**
Rule ID (e.g. `AA-INJ-001`) — run `agentaudit rules --explain <id>` to confirm.

**The flagged content**
The line or file agentaudit flagged (redact anything sensitive):

```
```

**Why it's benign**
Explain why this should not be a finding.

**Suggested fix (optional)**
A tighter regex, a `no_match` example to add, or a suppression that would be
appropriate here.
