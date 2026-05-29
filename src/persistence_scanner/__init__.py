"""Public package API for persistence_scanner."""

from .models import AutorunEntry, PersistenceFinding, Severity
from .rules import evaluate_autorun_entry, find_persistence_risks

__all__ = [
    "AutorunEntry",
    "PersistenceFinding",
    "Severity",
    "evaluate_autorun_entry",
    "find_persistence_risks",
]
