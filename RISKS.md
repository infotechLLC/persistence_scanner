# RISKS

- The extracted collectors have deterministic unit coverage and a GitHub-hosted Windows smoke
  check, but have not yet been validated on representative endpoints. Treat output as
  experimental until version/architecture coverage and Autoruns parity testing are complete.
- Authenticode status remains unknown, user-writability is inferred from environment roots rather
  than effective ACLs, and Startup shortcut targets are unresolved.
- Coverage is limited to Run keys, Startup folders, services, and executable scheduled-task
  actions; fileless WMI, COM, Winlogon/LSA, and other persistence mechanisms remain blind spots.
- Access-denied and malformed-source conditions are surfaced as diagnostics, but downstream
  consumers can still create false assurance if they discard those diagnostics.
- The legacy ZIP remains in the repository and could be mistaken for the maintained scanner.
