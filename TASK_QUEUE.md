# TASK_QUEUE

1. Validate collector coverage and failure behavior on supported Windows 10/11 and Server
   versions; compare results with a pinned Sysinternals Autoruns export.
2. Add native Authenticode verification, effective ACL evaluation, and `.lnk` target resolution
   without executing discovered content.
3. Add versioned JSON serialization plus baseline/diff workflows with atomic writes and schema
   validation.
4. Expand collection and rules to WMI event subscriptions, COM hijacks, Winlogon/LSA surfaces,
   and browser helper objects.
5. Add signed-publisher/hash allowlists with provenance, expiry, and auditable suppression output.
6. Remove the legacy ZIP from the release path after feature-parity evidence is recorded.
