# persistence_scanner

Windows persistence detection baseline with ATT&CK-oriented finding models.

## Why this exists

The repository previously held an opaque scanner artifact without an auditable source core.
This cycle establishes the source-controlled detection layer so findings, severities,
and triage logic can evolve in public review instead of being trapped inside a ZIP.

## What is included

- Normalized `AutorunEntry` and `PersistenceFinding` models.
- Rule-based triage for common autorun persistence surfaces.
- ATT&CK-aligned technique IDs for Run/RunOnce, Startup, and service patterns.
- Unit tests covering suspicious and benign persistence cases.

## Current scope

The current source baseline focuses on detection and triage, not host collection.
Existing host-collection artifacts can be incrementally migrated behind these models.
