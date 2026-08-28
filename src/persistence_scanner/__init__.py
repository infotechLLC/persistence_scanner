"""Public package API for persistence_scanner."""

from .models import AutorunEntry, PersistenceFinding, Severity
from .rules import evaluate_autorun_entry, find_persistence_risks
from .windows import (
    CollectionDiagnostic,
    CollectionResult,
    UnsupportedPlatformError,
    collect_windows_persistence,
)

__all__ = [
    "AutorunEntry",
    "CollectionDiagnostic",
    "CollectionResult",
    "PersistenceFinding",
    "Severity",
    "UnsupportedPlatformError",
    "collect_windows_persistence",
    "evaluate_autorun_entry",
    "find_persistence_risks",
]
