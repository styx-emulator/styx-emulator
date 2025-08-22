---
name: Bug report
about: Found a bug? Help us fix it!
title: ''
labels: C-Bug, S-Needs-Triage
assignees: ''

---

**Describe the bug**
A clear and concise description of what the bug is.

**To Reproduce**
Preferably a minimal code snippet or firmware to reproduce the bug.

**Expected behavior**
A clear and concise description of what you expected to happen.

**Logs**
If applicable, add logs to help debug your problem.

Add `styx_util::init_logging()` before any Styx operations and run with `RUST_LOG=debug cargo run ...` to get debug logs. Move to `trace` or `info` levels if there is too little or too much information.

**Misc Info (please complete the following information):**
 - Version [e.g. 1.2.0 OR <commit hash>]
 - OS: [e.g. Fedora 42, Debian 13, etc.]

**Additional context**
Add any other context about the problem here.
