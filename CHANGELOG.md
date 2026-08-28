# CHANGELOG

## 0.2.0 - 2026-08-28
- Added read-only Windows collectors for Run keys, Startup folders, services, and executable
  scheduled-task actions.
- Added explicit partial-collection diagnostics and non-Windows refusal semantics.
- Added tri-state evidence fields and ATT&CK `T1053.005` scheduled-task mapping.
- Added parser/collector regression tests, Ruff configuration, package build validation, and
  Linux/Windows CI with SHA-pinned third-party actions.
- Documented operational limitations and retained the legacy ZIP as provenance only.

## 2026-05-29
- Added the initial `persistence_scanner` Python package with normalized autorun and finding models.
- Added ATT&CK-oriented triage rules and regression tests for suspicious persistence surfaces.
- Replaced the placeholder security policy and added repository state/task tracking files.
