"""Read-only Windows persistence collection.

The collectors in this module enumerate configuration only. They never execute a
discovered command. Partial failures are returned as diagnostics instead of being
silently converted into an apparently complete scan.
"""

from __future__ import annotations

import hashlib
import os
import platform
import re
import shutil
import xml.etree.ElementTree as ET
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, replace
from pathlib import Path, PureWindowsPath
from typing import Any

from .models import AutorunEntry

_ENVIRONMENT_VARIABLE = re.compile(r"%([^%]+)%")
_EXECUTABLE_SUFFIX = re.compile(
    r"^(.+?\.(?:exe|com|cmd|bat|ps1|vbs|vbe|js|jse|wsf|wsh|msc|dll|sys|scr|lnk))"
    r"(?=\s|,|$)",
    re.IGNORECASE,
)
_MISSING = object()


class UnsupportedPlatformError(RuntimeError):
    """Raised when Windows collection is requested on another operating system."""


@dataclass(frozen=True, slots=True)
class CollectionDiagnostic:
    """A source that could not be read completely."""

    source: str
    location: str
    message: str


@dataclass(frozen=True, slots=True)
class CollectionResult:
    """Collected entries and explicit evidence of any coverage gaps."""

    entries: tuple[AutorunEntry, ...]
    diagnostics: tuple[CollectionDiagnostic, ...] = ()

    @property
    def complete(self) -> bool:
        return not self.diagnostics


@dataclass(frozen=True, slots=True)
class ScheduledTaskAction:
    """Executable action parsed from a Task Scheduler XML definition."""

    command: str
    arguments: str = ""
    working_directory: str = ""

    @property
    def command_line(self) -> str:
        command = self.command.strip()
        if any(character.isspace() for character in command) and not command.startswith('"'):
            command = f'"{command}"'
        return " ".join(part for part in (command, self.arguments.strip()) if part)


_RUN_LOCATIONS = (
    (
        "HKCU",
        "HKEY_CURRENT_USER",
        r"Software\Microsoft\Windows\CurrentVersion\Run",
        "user",
    ),
    (
        "HKCU",
        "HKEY_CURRENT_USER",
        r"Software\Microsoft\Windows\CurrentVersion\RunOnce",
        "user",
    ),
    (
        "HKCU",
        "HKEY_CURRENT_USER",
        r"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run",
        "user",
    ),
    (
        "HKLM",
        "HKEY_LOCAL_MACHINE",
        r"Software\Microsoft\Windows\CurrentVersion\Run",
        "machine",
    ),
    (
        "HKLM",
        "HKEY_LOCAL_MACHINE",
        r"Software\Microsoft\Windows\CurrentVersion\RunOnce",
        "machine",
    ),
    (
        "HKLM",
        "HKEY_LOCAL_MACHINE",
        r"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run",
        "machine",
    ),
)
_SERVICES_KEY = r"SYSTEM\CurrentControlSet\Services"


def collect_windows_persistence(
    *,
    environ: Mapping[str, str] | None = None,
) -> CollectionResult:
    """Collect Run keys, Startup folders, services, and scheduled tasks.

    The function intentionally refuses to fabricate results on non-Windows hosts.
    Callers can therefore distinguish an unsupported scan from a clean Windows host.
    """

    if platform.system().casefold() != "windows":
        raise UnsupportedPlatformError("Windows persistence collection requires Windows")

    import winreg  # Imported lazily so the package remains importable elsewhere.

    environment = dict(os.environ if environ is None else environ)
    results = (
        collect_registry_run_entries(winreg, environ=environment),
        collect_service_entries(winreg, environ=environment),
        collect_startup_entries(environ=environment),
        collect_scheduled_task_entries(environ=environment),
    )
    return _merge_results(results)


def collect_registry_run_entries(
    registry: Any,
    *,
    environ: Mapping[str, str] | None = None,
) -> CollectionResult:
    """Enumerate common per-user and machine Run/RunOnce registry values."""

    environment = dict(os.environ if environ is None else environ)
    entries: list[AutorunEntry] = []
    diagnostics: list[CollectionDiagnostic] = []
    seen: set[tuple[str, str, str]] = set()

    for hive_label, hive_attribute, subkey, scope in _RUN_LOCATIONS:
        root = getattr(registry, hive_attribute)
        for view_name, view_flag in _registry_views(registry):
            location = f"{hive_label}\\{subkey}"
            try:
                key = registry.OpenKey(
                    root,
                    subkey,
                    0,
                    getattr(registry, "KEY_READ", 0) | view_flag,
                )
            except OSError as exc:
                if not _is_missing_registry_error(exc):
                    diagnostics.append(_diagnostic("registry_run", location, exc))
                continue

            try:
                index = 0
                while True:
                    try:
                        name, value, value_type = registry.EnumValue(key, index)
                    except OSError as exc:
                        if not _is_enumeration_complete(exc):
                            diagnostics.append(_diagnostic("registry_run", location, exc))
                        break
                    index += 1
                    if not isinstance(value, str) or not value.strip():
                        continue

                    value_location = f"{location} [{view_name}]\\{name or '(Default)'}"
                    identity = (
                        view_name.casefold(),
                        value_location.casefold(),
                        value.casefold(),
                    )
                    if identity in seen:
                        continue
                    seen.add(identity)
                    entries.append(
                        _entry_from_command(
                            location=value_location,
                            command=value,
                            scope=scope,
                            source="registry_run",
                            name=name or "(Default)",
                            environ=environment,
                            metadata={
                                "registry_view": view_name,
                                "registry_value_type": str(value_type),
                            },
                        )
                    )
            finally:
                _close_registry_key(registry, key)

    return CollectionResult(tuple(entries), tuple(diagnostics))


def collect_service_entries(
    registry: Any,
    *,
    environ: Mapping[str, str] | None = None,
) -> CollectionResult:
    """Enumerate service ImagePath values without invoking Service Control Manager tools."""

    environment = dict(os.environ if environ is None else environ)
    entries: list[AutorunEntry] = []
    diagnostics: list[CollectionDiagnostic] = []
    root = registry.HKEY_LOCAL_MACHINE
    view_flag = getattr(registry, "KEY_WOW64_64KEY", 0)
    location = f"HKLM\\{_SERVICES_KEY}"

    try:
        services_key = registry.OpenKey(
            root,
            _SERVICES_KEY,
            0,
            getattr(registry, "KEY_READ", 0) | view_flag,
        )
    except OSError as exc:
        return CollectionResult((), (_diagnostic("service", location, exc),))

    try:
        index = 0
        while True:
            try:
                service_name = registry.EnumKey(services_key, index)
            except OSError as exc:
                if not _is_enumeration_complete(exc):
                    diagnostics.append(_diagnostic("service", location, exc))
                break
            index += 1
            service_location = f"{location}\\{service_name}"
            try:
                service_key = registry.OpenKey(
                    services_key,
                    service_name,
                    0,
                    getattr(registry, "KEY_READ", 0) | view_flag,
                )
            except OSError as exc:
                diagnostics.append(_diagnostic("service", service_location, exc))
                continue

            try:
                image_path = _query_registry_value(registry, service_key, "ImagePath")
                if not isinstance(image_path, str) or not image_path.strip():
                    continue

                start_type = _query_registry_value(registry, service_key, "Start")
                service_type = _query_registry_value(registry, service_key, "Type")
                try:
                    service_dll = _query_service_dll(registry, service_key, view_flag)
                except OSError as exc:
                    diagnostics.append(
                        _diagnostic("service", f"{service_location}\\Parameters", exc)
                    )
                    service_dll = _MISSING
                service_metadata = {
                    "service_name": service_name,
                    "start_type": "" if start_type is _MISSING else str(start_type),
                    "service_type": "" if service_type is _MISSING else str(service_type),
                }
                image_metadata = {**service_metadata, "registry_value": "ImagePath"}
                if isinstance(service_dll, str) and service_dll.strip():
                    image_metadata["service_dll"] = service_dll
                entries.append(
                    _entry_from_command(
                        location=service_location,
                        command=image_path,
                        scope="machine",
                        source="service",
                        name=service_name,
                        environ=environment,
                        metadata=image_metadata,
                    )
                )
                if isinstance(service_dll, str) and service_dll.strip():
                    entries.append(
                        _entry_from_command(
                            location=f"{service_location}\\Parameters\\ServiceDll",
                            command=service_dll,
                            scope="machine",
                            source="service",
                            name=f"{service_name}:ServiceDll",
                            environ=environment,
                            metadata={**service_metadata, "registry_value": "ServiceDll"},
                        )
                    )
            except OSError as exc:
                diagnostics.append(_diagnostic("service", service_location, exc))
            finally:
                _close_registry_key(registry, service_key)
    finally:
        _close_registry_key(registry, services_key)

    return CollectionResult(tuple(entries), tuple(diagnostics))


def collect_startup_entries(
    *,
    environ: Mapping[str, str] | None = None,
    roots: Iterable[tuple[str, str]] | None = None,
) -> CollectionResult:
    """Enumerate files in current-user and all-users Startup folders."""

    environment = dict(os.environ if environ is None else environ)
    startup_roots = tuple(roots) if roots is not None else _default_startup_roots(environment)
    entries: list[AutorunEntry] = []
    diagnostics: list[CollectionDiagnostic] = []

    for scope, root_text in startup_roots:
        root = Path(root_text)
        try:
            root.stat()
        except FileNotFoundError:
            continue
        except OSError as exc:
            diagnostics.append(_diagnostic("startup_folder", str(root), exc))
            continue
        try:
            directory_entries = sorted(os.scandir(root), key=lambda item: item.name.casefold())
        except OSError as exc:
            diagnostics.append(_diagnostic("startup_folder", str(root), exc))
            continue

        for directory_entry in directory_entries:
            try:
                if not directory_entry.is_file(follow_symlinks=False):
                    continue
            except OSError as exc:
                diagnostics.append(_diagnostic("startup_folder", directory_entry.path, exc))
                continue

            entry = _entry_from_command(
                location=f"Startup\\{directory_entry.path}",
                command=directory_entry.path,
                scope=scope,
                source="startup_folder",
                name=directory_entry.name,
                environ=environment,
                metadata={},
                known_file_path=directory_entry.path,
            )
            if scope == "user":
                entry = replace(entry, user_writable_path=True)
            entries.append(entry)

    return CollectionResult(tuple(entries), tuple(diagnostics))


def collect_scheduled_task_entries(
    *,
    environ: Mapping[str, str] | None = None,
    task_root: str | Path | None = None,
) -> CollectionResult:
    """Parse executable actions from on-disk Task Scheduler XML definitions."""

    environment = dict(os.environ if environ is None else environ)
    root = Path(task_root) if task_root is not None else _default_task_root(environment)
    if root is None:
        diagnostic = CollectionDiagnostic(
            source="scheduled_task",
            location="%SystemRoot%\\System32\\Tasks",
            message="SystemRoot is not available",
        )
        return CollectionResult((), (diagnostic,))
    if not root.exists():
        diagnostic = CollectionDiagnostic(
            source="scheduled_task",
            location=str(root),
            message="task directory does not exist",
        )
        return CollectionResult((), (diagnostic,))

    entries: list[AutorunEntry] = []
    diagnostics: list[CollectionDiagnostic] = []

    def record_walk_error(exc: OSError) -> None:
        diagnostics.append(_diagnostic("scheduled_task", exc.filename or str(root), exc))

    for directory, directory_names, filenames in os.walk(root, onerror=record_walk_error):
        directory_names.sort(key=str.casefold)
        for filename in sorted(filenames, key=str.casefold):
            task_path = Path(directory, filename)
            try:
                task_xml = task_path.read_bytes()
                actions, user_id = parse_scheduled_task_xml(task_xml)
            except (OSError, ET.ParseError, ValueError) as exc:
                diagnostics.append(_diagnostic("scheduled_task", str(task_path), exc))
                continue

            relative_name = str(task_path.relative_to(root)).replace(os.sep, "\\")
            scope = _task_scope(user_id)
            for action_index, action in enumerate(actions, start=1):
                suffix = f"#Action{action_index}" if len(actions) > 1 else ""
                target_path = _scheduled_task_target(action, environment)
                metadata = {
                    "task_name": relative_name,
                    "action_index": str(action_index),
                }
                if user_id:
                    metadata["task_user"] = user_id
                if action.working_directory:
                    metadata["working_directory"] = action.working_directory
                entries.append(
                    _entry_from_command(
                        location=f"Task Scheduler\\{relative_name}{suffix}",
                        command=action.command_line,
                        scope=scope,
                        source="scheduled_task",
                        name=relative_name,
                        environ=environment,
                        metadata=metadata,
                        known_file_path=target_path,
                        search_path=False,
                    )
                )

    return CollectionResult(tuple(entries), tuple(diagnostics))


def parse_scheduled_task_xml(
    task_xml: bytes | str,
) -> tuple[tuple[ScheduledTaskAction, ...], str]:
    """Return Exec actions and the configured principal from Task Scheduler XML."""

    root = ET.fromstring(task_xml)
    actions: list[ScheduledTaskAction] = []
    user_id = ""

    for element in root.iter():
        if _local_name(element.tag) == "UserId" and element.text and not user_id:
            user_id = element.text.strip()
        if _local_name(element.tag) != "Exec":
            continue

        fields: dict[str, str] = {}
        for child in element:
            name = _local_name(child.tag)
            if child.text:
                fields[name] = child.text.strip()
        command = fields.get("Command", "")
        if command:
            actions.append(
                ScheduledTaskAction(
                    command=command,
                    arguments=fields.get("Arguments", ""),
                    working_directory=fields.get("WorkingDirectory", ""),
                )
            )

    return tuple(actions), user_id


def extract_executable_path(
    command: str,
    environ: Mapping[str, str] | None = None,
) -> str | None:
    """Best-effort extraction of a Windows executable or script path."""

    expanded = expand_windows_environment(command, environ or {})
    candidate = expanded.strip()
    if candidate.startswith("\\??\\"):
        candidate = candidate[4:]
    if not candidate:
        return None

    if candidate.startswith('"'):
        closing_quote = candidate.find('"', 1)
        if closing_quote > 1:
            return candidate[1:closing_quote]

    match = _EXECUTABLE_SUFFIX.match(candidate)
    if match:
        return match.group(1).strip('"')

    first_token = candidate.split(maxsplit=1)[0].strip('"')
    return first_token or None


def expand_windows_environment(command: str, environ: Mapping[str, str]) -> str:
    """Expand percent-delimited environment variables case-insensitively."""

    casefolded_environment = {key.casefold(): value for key, value in environ.items()}

    def replace_variable(match: re.Match[str]) -> str:
        return casefolded_environment.get(match.group(1).casefold(), match.group(0))

    expanded = _ENVIRONMENT_VARIABLE.sub(replace_variable, command)
    system_root = casefolded_environment.get("systemroot")
    if system_root and expanded.casefold().startswith("\\systemroot\\"):
        expanded = system_root.rstrip("\\/") + expanded[len(r"\SystemRoot") :]
    return expanded


def _entry_from_command(
    *,
    location: str,
    command: str,
    scope: str,
    source: str,
    name: str,
    environ: Mapping[str, str],
    metadata: Mapping[str, str],
    known_file_path: str | None = None,
    search_path: bool = True,
) -> AutorunEntry:
    expanded_command = expand_windows_environment(command, environ)
    target = known_file_path or extract_executable_path(expanded_command, environ)
    resolved_target = _resolve_target(target, search_path=search_path)
    exists_on_disk: bool | None = None
    digest: str | None = None

    if resolved_target and _is_absolute_path(resolved_target):
        try:
            exists_on_disk = os.path.isfile(resolved_target)
        except OSError:
            exists_on_disk = None
        if exists_on_disk:
            digest = _sha256_file(resolved_target)

    collected_metadata = {
        "source": source,
        "name": name,
        **{key: str(value) for key, value in metadata.items()},
    }
    if resolved_target:
        collected_metadata["target_path"] = resolved_target
    if digest:
        collected_metadata["sha256"] = digest

    writable_subject = resolved_target or expanded_command
    return AutorunEntry(
        location=location,
        command=command,
        scope=scope,
        signed=None,
        exists_on_disk=exists_on_disk,
        user_writable_path=_is_probably_user_writable(writable_subject, environ),
        metadata=collected_metadata,
    )


def _resolve_target(target: str | None, *, search_path: bool = True) -> str | None:
    if not target:
        return None
    if _is_absolute_path(target):
        return target
    if search_path and "\\" not in target and "/" not in target:
        return shutil.which(target) or target
    return target


def _scheduled_task_target(
    action: ScheduledTaskAction,
    environ: Mapping[str, str],
) -> str | None:
    target = extract_executable_path(action.command_line, environ)
    if not target or _is_absolute_path(target):
        return target

    working_directory = expand_windows_environment(action.working_directory, environ)
    working_directory = working_directory.strip().strip('"')
    if not working_directory or not _is_absolute_path(working_directory):
        return target
    return str(PureWindowsPath(working_directory) / PureWindowsPath(target))


def _is_absolute_path(path: str) -> bool:
    return PureWindowsPath(path).is_absolute() or Path(path).is_absolute()


def _is_probably_user_writable(path_or_command: str, environ: Mapping[str, str]) -> bool:
    normalized = path_or_command.replace("/", "\\").casefold()
    casefolded_environment = {key.casefold(): value for key, value in environ.items()}
    writable_roots = (
        casefolded_environment.get("userprofile"),
        casefolded_environment.get("appdata"),
        casefolded_environment.get("localappdata"),
        casefolded_environment.get("temp"),
        casefolded_environment.get("tmp"),
        casefolded_environment.get("public"),
    )
    for root in writable_roots:
        if not root:
            continue
        normalized_root = root.replace("/", "\\").rstrip("\\").casefold()
        start = normalized.find(normalized_root)
        while start >= 0:
            end = start + len(normalized_root)
            if end == len(normalized) or normalized[end] in {"\\", '"', "'", " ", "\t"}:
                return True
            start = normalized.find(normalized_root, start + 1)
    return False


def _sha256_file(path: str) -> str | None:
    digest = hashlib.sha256()
    try:
        with open(path, "rb") as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(chunk)
    except OSError:
        return None
    return digest.hexdigest()


def _default_startup_roots(environ: Mapping[str, str]) -> tuple[tuple[str, str], ...]:
    roots: list[tuple[str, str]] = []
    casefolded_environment = {key.casefold(): value for key, value in environ.items()}
    appdata = casefolded_environment.get("appdata")
    program_data = casefolded_environment.get("programdata")
    suffix = Path("Microsoft", "Windows", "Start Menu", "Programs", "Startup")
    if appdata:
        roots.append(("user", str(Path(appdata, suffix))))
    if program_data:
        roots.append(("machine", str(Path(program_data, suffix))))
    return tuple(roots)


def _default_task_root(environ: Mapping[str, str]) -> Path | None:
    system_root = next(
        (value for key, value in environ.items() if key.casefold() == "systemroot"),
        None,
    )
    if not system_root:
        return None
    return Path(system_root, "System32", "Tasks")


def _registry_views(registry: Any) -> tuple[tuple[str, int], ...]:
    view_64 = getattr(registry, "KEY_WOW64_64KEY", None)
    view_32 = getattr(registry, "KEY_WOW64_32KEY", None)
    if view_64 is None or view_32 is None:
        return (("native", 0),)
    return (("64-bit", view_64), ("32-bit", view_32))


def _query_registry_value(registry: Any, key: Any, name: str) -> object:
    try:
        value, _value_type = registry.QueryValueEx(key, name)
    except OSError as exc:
        if _is_missing_registry_error(exc):
            return _MISSING
        raise
    return value


def _query_service_dll(registry: Any, service_key: Any, view_flag: int) -> object:
    try:
        parameters_key = registry.OpenKey(
            service_key,
            "Parameters",
            0,
            getattr(registry, "KEY_READ", 0) | view_flag,
        )
    except OSError as exc:
        if _is_missing_registry_error(exc):
            return _MISSING
        raise
    try:
        return _query_registry_value(registry, parameters_key, "ServiceDll")
    finally:
        _close_registry_key(registry, parameters_key)


def _close_registry_key(registry: Any, key: Any) -> None:
    close_key = getattr(registry, "CloseKey", None)
    if close_key is not None:
        close_key(key)
        return
    close = getattr(key, "Close", None) or getattr(key, "close", None)
    if close is not None:
        close()


def _is_missing_registry_error(exc: OSError) -> bool:
    return isinstance(exc, FileNotFoundError) or getattr(exc, "winerror", None) in {2, 3}


def _is_enumeration_complete(exc: OSError) -> bool:
    winerror = getattr(exc, "winerror", None)
    return winerror is None or winerror == 259


def _diagnostic(source: str, location: str, exc: BaseException) -> CollectionDiagnostic:
    detail = str(exc).strip() or exc.__class__.__name__
    return CollectionDiagnostic(source=source, location=location, message=detail)


def _local_name(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _task_scope(user_id: str) -> str:
    machine_principals = {
        "system",
        "local service",
        "network service",
        "s-1-5-18",
        "s-1-5-19",
        "s-1-5-20",
    }
    return "machine" if not user_id or user_id.casefold() in machine_principals else "user"


def _merge_results(results: Iterable[CollectionResult]) -> CollectionResult:
    entries: list[AutorunEntry] = []
    diagnostics: list[CollectionDiagnostic] = []
    seen: set[tuple[str, str]] = set()
    for result in results:
        diagnostics.extend(result.diagnostics)
        for entry in result.entries:
            identity = (entry.location.casefold(), entry.command.casefold())
            if identity in seen:
                continue
            seen.add(identity)
            entries.append(entry)
    entries.sort(key=lambda entry: (entry.location.casefold(), entry.command.casefold()))
    diagnostics.sort(key=lambda item: (item.source, item.location.casefold(), item.message))
    return CollectionResult(tuple(entries), tuple(diagnostics))
