"""Normalized models for persistence triage."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import Enum


class Severity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"

    @classmethod
    def max(cls, *levels: Severity) -> Severity:
        order = {cls.LOW: 0, cls.MEDIUM: 1, cls.HIGH: 2}
        return max(levels, key=lambda level: order[level])


@dataclass(frozen=True, slots=True)
class AutorunEntry:
    """Host-collected autorun record normalized for rule evaluation."""

    location: str
    command: str
    scope: str = "machine"
    signed: bool | None = None
    exists_on_disk: bool | None = None
    user_writable_path: bool | None = None
    metadata: Mapping[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "metadata", dict(self.metadata))


@dataclass(frozen=True, slots=True)
class PersistenceFinding:
    """ATT&CK-oriented finding emitted by triage rules."""

    location: str
    technique_id: str
    severity: Severity
    rationale: str
    evidence: tuple[str, ...] = ()
