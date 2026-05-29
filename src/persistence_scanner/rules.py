"""Rule-based triage for common Windows persistence surfaces."""

from __future__ import annotations

from collections.abc import Iterable

from .models import AutorunEntry, PersistenceFinding, Severity

SUSPICIOUS_COMMAND_HINTS = (
    "powershell -enc",
    "cmd.exe /c",
    "rundll32",
    "wscript",
    "mshta",
    "appdata\\",
    "temp\\",
)


def evaluate_autorun_entry(entry: AutorunEntry) -> PersistenceFinding | None:
    """Return a finding when an autorun entry looks persistence-heavy or suspicious."""
    location_lower = entry.location.lower()
    command_lower = entry.command.lower()
    technique_id = _technique_for_location(location_lower)

    rationale: list[str] = []
    severity = Severity.LOW

    if not entry.exists_on_disk:
        rationale.append("target executable is missing on disk")
        severity = Severity.max(severity, Severity.MEDIUM)

    if entry.user_writable_path:
        rationale.append("target resolves to a user-writable path")
        severity = Severity.max(severity, Severity.HIGH)

    if not entry.signed:
        rationale.append("target binary is unsigned")
        severity = Severity.max(severity, Severity.MEDIUM)

    matched_hints = [hint for hint in SUSPICIOUS_COMMAND_HINTS if hint in command_lower]
    if matched_hints:
        rationale.append(
            "command contains suspicious launcher patterns: " + ", ".join(sorted(matched_hints))
        )
        severity = Severity.max(severity, Severity.HIGH)

    if entry.scope.lower() == "user" and technique_id == "T1547.001":
        rationale.append("user-scoped autorun entry widens persistence surface")
        severity = Severity.max(severity, Severity.MEDIUM)

    if not rationale:
        return None

    return PersistenceFinding(
        location=entry.location,
        technique_id=technique_id,
        severity=severity,
        rationale="; ".join(rationale),
        evidence=(entry.command,),
    )


def find_persistence_risks(entries: Iterable[AutorunEntry]) -> list[PersistenceFinding]:
    """Evaluate a batch of autorun entries and return the suspicious subset."""
    findings = [finding for finding in (evaluate_autorun_entry(entry) for entry in entries) if finding]
    severity_rank = {Severity.HIGH: 0, Severity.MEDIUM: 1, Severity.LOW: 2}
    return sorted(findings, key=lambda finding: (severity_rank[finding.severity], finding.location.lower()))


def _technique_for_location(location_lower: str) -> str:
    if "startup" in location_lower or "\\run" in location_lower:
        return "T1547.001"
    if "service" in location_lower:
        return "T1543.003"
    return "T1547"
