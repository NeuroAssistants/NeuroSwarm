# NeuroSwarm changelog

## 2026-11-25

- Live Events shows the HTTP result recorded for a request alongside the process exit code. For example, a request can return HTTP 401 while curl exits successfully. Visits, searches and page snapshots have distinct labels. Structured web evidence was verified with Codex and Claude Code. [Changes](https://github.com/NeuroAssistants/NeuroSwarm/commit/e71e6d4f590878c434c06b13588b605a8b052721)
- Command details distinguish empty output from missing evidence when the observer records the reason. Alerts with a recorded source event reopen its historical result. Older records can only show evidence captured at the time. [Changes](https://github.com/NeuroAssistants/NeuroSwarm/commit/e71e6d4f590878c434c06b13588b605a8b052721)
- Files & Workspace associates supported file reads, Python scripts and edits with their own calls. An open event updates when its output arrives later. [Changes](https://github.com/NeuroAssistants/NeuroSwarm/commit/4c4d7a4)
