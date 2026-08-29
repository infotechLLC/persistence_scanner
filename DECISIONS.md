# DECISIONS

## 2026-05-29
- Started by extracting the auditable detection layer into source control instead of trying to extend the opaque ZIP artifact directly.
- Normalized findings around ATT&CK technique IDs and severity so future collectors and UIs can share one contract.
- Focused the initial rules on high-signal autorun surfaces that are easy to explain and test.

## 2026-08-28
- Migrated collection as read-only standard-library code and rejected the legacy behavior that
  fabricated persistence records on non-Windows systems.
- Returned partial-coverage diagnostics as first-class scan output because an unread source is
  materially different from an empty source.
- Represented unavailable evidence as `None`; unknown signature or file state must not silently
  become trusted or suspicious.
- Parsed scheduled-task definitions from on-disk XML instead of invoking discovered commands or
  relying on locale-sensitive command output.
