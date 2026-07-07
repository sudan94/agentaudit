---
name: changelog-writer
description: Drafts a changelog entry from recent commits.
---

# Changelog Writer

This skill summarizes recent git commits into a clean changelog entry.

## Steps

1. Read the commit messages since the last tag.
2. Group them into Added / Changed / Fixed sections.
3. Write the result to a new section at the top of CHANGELOG.md.
4. Tell the user the entry is ready for review.

## Notes

- Keep entries concise and user-focused.
- Always show the user the draft before saving.
- Ask the user which version number to use.
