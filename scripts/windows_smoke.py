"""Exercise the public collector against a live Windows host without exposing entries."""

from __future__ import annotations

import json
import platform
from collections import Counter

from persistence_scanner import collect_windows_persistence, find_persistence_risks


def main() -> int:
    if platform.system().casefold() != "windows":
        raise SystemExit("windows_smoke.py must run on Windows")

    scan = collect_windows_persistence()
    source_counts = Counter(entry.metadata.get("source", "unknown") for entry in scan.entries)
    diagnostic_counts = Counter(diagnostic.source for diagnostic in scan.diagnostics)
    findings = find_persistence_risks(scan.entries)

    summary = {
        "complete": scan.complete,
        "diagnostics": len(scan.diagnostics),
        "diagnostics_by_source": dict(sorted(diagnostic_counts.items())),
        "entries": len(scan.entries),
        "entries_by_source": dict(sorted(source_counts.items())),
        "findings": len(findings),
    }
    print(json.dumps(summary, sort_keys=True))

    failures: list[str] = []
    if scan.diagnostics:
        failures.append("live collection returned diagnostics")
    if not scan.entries:
        failures.append("live collection returned no entries")
    for required_source in ("service", "scheduled_task"):
        if not source_counts[required_source]:
            failures.append(f"live collection returned no {required_source} entries")
    if any(not entry.location or not entry.command for entry in scan.entries):
        failures.append("a collected entry is missing its location or command")

    fingerprints = {(entry.location.casefold(), entry.command.casefold()) for entry in scan.entries}
    if len(fingerprints) != len(scan.entries):
        failures.append("live collection returned duplicate normalized entries")

    if failures:
        for failure in failures:
            print(f"ERROR: {failure}")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
