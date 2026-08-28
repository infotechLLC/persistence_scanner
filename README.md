# persistence_scanner

Auditable, read-only Windows persistence collection with ATT&CK-oriented triage.

The project replaces an opaque proof-of-concept archive with reviewable package code. It
collects persistence configuration, normalizes it as `AutorunEntry` records, and applies
explainable rules. A finding is triage evidence, not a malware verdict.

## Implemented surfaces

- `HKCU` and `HKLM` Run, RunOnce, and Explorer policy Run values, including 32-bit and
  64-bit registry views.
- Current-user and all-users Startup folders.
- Windows service `ImagePath` values and associated `ServiceDll` metadata.
- Task Scheduler XML definitions with executable (`Exec`) actions.
- ATT&CK mappings for Registry Run Keys / Startup Folder (`T1547.001`), Windows services
  (`T1543.003`), and scheduled tasks (`T1053.005`).

Collectors enumerate configuration only and never execute a discovered command. File hashes
are SHA-256. A partial read is returned as a diagnostic instead of being silently reported as
a clean host.

## Quick start

Python 3.10 or newer is required.

```powershell
py -m pip install .
```

Run collection from an elevated Windows terminal when full machine-level coverage is needed:

```python
from persistence_scanner import collect_windows_persistence, find_persistence_risks

scan = collect_windows_persistence()
findings = find_persistence_risks(scan.entries)

for finding in findings:
    print(finding.severity.value, finding.technique_id, finding.location)

for diagnostic in scan.diagnostics:
    print("INCOMPLETE", diagnostic.source, diagnostic.location, diagnostic.message)
```

`scan.complete` is false whenever a source could not be read or parsed. Preserve the
diagnostics with any exported result; otherwise a permission failure can be mistaken for
absence of persistence.

## Development

```bash
python -m pip install -e ".[dev]"
python -m ruff check .
python -m ruff format --check .
python -m pytest
python -m build
```

CI runs linting, tests, and package builds on Linux with Python 3.10, 3.12, and 3.14,
plus a Windows/Python 3.12 compatibility job. GitHub's repository-level default CodeQL setup
analyzes Python on pull requests.

## Evidence semantics and limitations

The `signed`, `exists_on_disk`, and `user_writable_path` fields are tri-state: `True`,
`False`, or `None` when unknown. Unknown facts are not treated as malicious.

Current limitations are material:

- Authenticode verification is not implemented, so collected signature state is unknown.
- User-writable path detection is an environment-root heuristic, not a Windows ACL check.
- Startup `.lnk` targets are not resolved; the shortcut itself is hashed.
- Non-`Exec` scheduled-task actions, WMI event subscriptions, COM hijacks, browser helper
  objects, and additional Winlogon/LSA surfaces are not yet collected.
- The collectors need validation on a representative Windows version/architecture matrix and
  against trusted Sysinternals Autoruns output before operational use.

The legacy `windows_persistence_scanner.zip` is retained only as provenance while behavior is
migrated. Do not deploy or execute the archive as the maintained implementation.
