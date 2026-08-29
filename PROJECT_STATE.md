# PROJECT_STATE

## Mission
Provide an auditable Windows persistence detection and triage layer aligned to ATT&CK persistence surfaces.

## Development State
DEVELOPMENT / EXPERIMENTAL

## 2026-08-29 Correctness Follow-up
- Split Windows service `ImagePath` and `ServiceDll` data into separate normalized targets so
  findings cannot attribute DLL risk to a host process.
- Guarded Startup-root metadata reads and preserved access failures as collection diagnostics.

## 2026-08-28 Cycle Summary
- Extracted read-only collectors for Run/RunOnce keys, Startup folders, Windows services, and
  Task Scheduler XML from the legacy archive into source-controlled package code.
- Added explicit partial-scan diagnostics instead of silently converting collection failures
  into empty results.
- Made signature, file-existence, and user-writability evidence tri-state so unknown evidence
  is not misclassified.
- Added scheduled-task ATT&CK mapping, deterministic parser/collector tests, package linting,
  distribution builds, real Linux/Windows CI jobs, a read-only live Windows smoke check, and
  verified default CodeQL Python analysis.

## Validation
- Local Linux/Python 3.12: Ruff passed; 15 tests passed; sdist and wheel builds passed.
- Pull request CI passed on Linux/Python 3.10, 3.12, and 3.14 and Windows/Python 3.12; GitHub's
  default CodeQL Python analysis also passed.
- Pull-request CI now requires an aggregate-only live collection smoke check on its hosted
  Windows runner. Representative endpoint coverage and Sysinternals Autoruns parity remain
  unvalidated.
