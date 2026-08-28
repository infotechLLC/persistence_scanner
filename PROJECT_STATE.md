# PROJECT_STATE

## Mission
Provide an auditable Windows persistence detection and triage layer aligned to ATT&CK persistence surfaces.

## Development State
DEVELOPMENT / EXPERIMENTAL

## 2026-08-28 Cycle Summary
- Extracted read-only collectors for Run/RunOnce keys, Startup folders, Windows services, and
  Task Scheduler XML from the legacy archive into source-controlled package code.
- Added explicit partial-scan diagnostics instead of silently converting collection failures
  into empty results.
- Made signature, file-existence, and user-writability evidence tri-state so unknown evidence
  is not misclassified.
- Added scheduled-task ATT&CK mapping, deterministic parser/collector tests, package linting,
  distribution builds, real Linux/Windows CI jobs, and verified default CodeQL Python analysis.

## Validation
- Local Linux/Python 3.12: Ruff passed; 13 tests passed; sdist and wheel builds passed.
- Pull request CI passed on Linux/Python 3.10, 3.12, and 3.14 and Windows/Python 3.12; GitHub's
  default CodeQL Python analysis also passed.
- Live-host Windows collection and Sysinternals Autoruns parity remain unvalidated.
