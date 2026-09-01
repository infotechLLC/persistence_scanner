from __future__ import annotations

import hashlib
import platform
from dataclasses import dataclass
from pathlib import Path

import pytest

from persistence_scanner import (
    AutorunEntry,
    Severity,
    UnsupportedPlatformError,
    collect_windows_persistence,
    evaluate_autorun_entry,
)
from persistence_scanner.windows import (
    collect_registry_run_entries,
    collect_scheduled_task_entries,
    collect_service_entries,
    collect_startup_entries,
    expand_windows_environment,
    extract_executable_path,
    parse_scheduled_task_xml,
)


@dataclass(frozen=True)
class _FakeKey:
    path: str
    view: int = 0


class _FakeRegistry:
    HKEY_CURRENT_USER = "HKCU"
    HKEY_LOCAL_MACHINE = "HKLM"
    KEY_READ = 1

    def __init__(self, nodes: dict[str, dict[str, object]]) -> None:
        self.nodes = nodes

    def OpenKey(
        self,
        root: str | _FakeKey,
        subkey: str,
        _reserved: int,
        _access: int,
    ) -> _FakeKey:
        base = root.path if isinstance(root, _FakeKey) else root
        path = f"{base}\\{subkey}"
        if path not in self.nodes:
            raise FileNotFoundError(path)
        return _FakeKey(path)

    def EnumValue(self, key: _FakeKey, index: int) -> tuple[str, object, int]:
        values = self.nodes[key.path].get("values", [])
        assert isinstance(values, list)
        try:
            value = values[index]
        except IndexError as exc:
            raise OSError from exc
        assert isinstance(value, tuple)
        return value

    def EnumKey(self, key: _FakeKey, index: int) -> str:
        subkeys = self.nodes[key.path].get("subkeys", [])
        assert isinstance(subkeys, list)
        try:
            value = subkeys[index]
        except IndexError as exc:
            raise OSError from exc
        assert isinstance(value, str)
        return value

    def QueryValueEx(self, key: _FakeKey, name: str) -> tuple[object, int]:
        named_values = self.nodes[key.path].get("named_values", {})
        assert isinstance(named_values, dict)
        if name not in named_values:
            raise FileNotFoundError(name)
        return named_values[name], 1

    def CloseKey(self, _key: _FakeKey) -> None:
        return None


class _DeniedParametersRegistry(_FakeRegistry):
    def OpenKey(
        self,
        root: str | _FakeKey,
        subkey: str,
        reserved: int,
        access: int,
    ) -> _FakeKey:
        if isinstance(root, _FakeKey) and subkey == "Parameters":
            raise PermissionError("service parameters denied")
        return super().OpenKey(root, subkey, reserved, access)


class _FakeViewRegistry(_FakeRegistry):
    KEY_WOW64_64KEY = 0x0100
    KEY_WOW64_32KEY = 0x0200

    def OpenKey(
        self,
        root: str | _FakeKey,
        subkey: str,
        reserved: int,
        access: int,
    ) -> _FakeKey:
        key = super().OpenKey(root, subkey, reserved, access)
        view = access & (self.KEY_WOW64_64KEY | self.KEY_WOW64_32KEY)
        return _FakeKey(key.path, view)

    def EnumValue(self, key: _FakeKey, index: int) -> tuple[str, object, int]:
        values_by_view = self.nodes[key.path].get("values_by_view", {})
        assert isinstance(values_by_view, dict)
        values = values_by_view.get(key.view, [])
        assert isinstance(values, list)
        try:
            value = values[index]
        except IndexError as exc:
            raise OSError from exc
        assert isinstance(value, tuple)
        return value


def test_extract_executable_path_handles_windows_quoting_and_environment() -> None:
    environment = {"SystemRoot": r"C:\Windows"}

    assert (
        extract_executable_path(
            r'"%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile',
            environment,
        )
        == r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
    )
    assert (
        extract_executable_path(
            r"C:\Program Files\Vendor Agent\agent.exe --service",
            environment,
        )
        == r"C:\Program Files\Vendor Agent\agent.exe"
    )
    assert expand_windows_environment(r"\SystemRoot\System32\drivers\safe.sys", environment) == (
        r"C:\Windows\System32\drivers\safe.sys"
    )


def test_registry_run_collector_normalizes_values_without_executing_them() -> None:
    run_key = r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run"
    registry = _FakeRegistry(
        {
            run_key: {
                "values": [
                    (
                        "Updater",
                        r'"C:\Users\alice\AppData\Roaming\updater.exe" --background',
                        1,
                    )
                ]
            }
        }
    )

    result = collect_registry_run_entries(
        registry,
        environ={
            "USERPROFILE": r"C:\Users\alice",
            "APPDATA": r"C:\Users\alice\AppData\Roaming",
        },
    )

    assert result.complete
    assert len(result.entries) == 1
    entry = result.entries[0]
    assert entry.scope == "user"
    assert entry.user_writable_path is True
    assert entry.signed is None
    assert entry.metadata["source"] == "registry_run"


def test_registry_run_collector_preserves_identical_values_from_both_views() -> None:
    run_key = r"HKLM\Software\Microsoft\Windows\CurrentVersion\Run"
    value = ("Updater", r"C:\Program Files\Vendor\updater.exe", 1)
    registry = _FakeViewRegistry(
        {
            run_key: {
                "values_by_view": {
                    _FakeViewRegistry.KEY_WOW64_64KEY: [value],
                    _FakeViewRegistry.KEY_WOW64_32KEY: [value],
                }
            }
        }
    )

    result = collect_registry_run_entries(registry, environ={})

    assert result.complete
    assert len(result.entries) == 2
    assert {entry.metadata["registry_view"] for entry in result.entries} == {
        "32-bit",
        "64-bit",
    }
    assert len({entry.location for entry in result.entries}) == 2
    assert all(f"[{entry.metadata['registry_view']}]" in entry.location for entry in result.entries)


def test_user_profile_matching_requires_a_path_boundary() -> None:
    run_key = r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run"
    registry = _FakeRegistry(
        {
            run_key: {
                "values": [
                    ("OtherUser", r"C:\Users\alice2\agent.exe", 1),
                ]
            }
        }
    )

    result = collect_registry_run_entries(
        registry,
        environ={"USERPROFILE": r"C:\Users\alice"},
    )

    assert result.entries[0].user_writable_path is False


def test_service_collector_emits_service_dll_as_separate_target_evidence(
    tmp_path: Path,
) -> None:
    service_root = r"HKLM\SYSTEM\CurrentControlSet\Services"
    service_key = service_root + r"\TelemetryAgent"
    parameters_key = service_key + r"\Parameters"
    service_dll = tmp_path / "telemetry.dll"
    service_dll.write_bytes(b"service dll fixture")
    registry = _FakeRegistry(
        {
            service_root: {"subkeys": ["TelemetryAgent"]},
            service_key: {
                "named_values": {
                    "ImagePath": r"%SystemRoot%\System32\svchost.exe -k netsvcs",
                    "Start": 2,
                    "Type": 32,
                }
            },
            parameters_key: {
                "named_values": {
                    "ServiceDll": str(service_dll),
                }
            },
        }
    )

    result = collect_service_entries(
        registry,
        environ={
            "SystemRoot": r"C:\Windows",
            "TEMP": str(tmp_path),
        },
    )

    assert result.complete
    assert len(result.entries) == 2
    image_entry = next(
        entry for entry in result.entries if entry.metadata["registry_value"] == "ImagePath"
    )
    dll_entry = next(
        entry for entry in result.entries if entry.metadata["registry_value"] == "ServiceDll"
    )

    assert image_entry.command == r"%SystemRoot%\System32\svchost.exe -k netsvcs"
    assert image_entry.user_writable_path is False
    assert image_entry.metadata["service_dll"] == str(service_dll)
    assert dll_entry.location.endswith(r"TelemetryAgent\Parameters\ServiceDll")
    assert dll_entry.command == str(service_dll)
    assert dll_entry.metadata["target_path"] == str(service_dll)
    assert dll_entry.metadata["sha256"] == hashlib.sha256(service_dll.read_bytes()).hexdigest()
    assert dll_entry.exists_on_disk is True
    assert dll_entry.user_writable_path is True
    assert dll_entry.metadata["start_type"] == "2"

    finding = evaluate_autorun_entry(dll_entry)
    assert finding is not None
    assert finding.evidence == (str(service_dll),)


def test_service_is_retained_when_optional_parameters_are_denied() -> None:
    service_root = r"HKLM\SYSTEM\CurrentControlSet\Services"
    service_key = service_root + r"\ProtectedService"
    registry = _DeniedParametersRegistry(
        {
            service_root: {"subkeys": ["ProtectedService"]},
            service_key: {
                "named_values": {
                    "ImagePath": r"C:\Windows\System32\protected.exe",
                    "Start": 2,
                    "Type": 16,
                }
            },
        }
    )

    result = collect_service_entries(registry, environ={})

    assert len(result.entries) == 1
    assert not result.complete
    assert result.diagnostics[0].location.endswith(r"ProtectedService\Parameters")


def test_startup_collector_hashes_the_artifact_and_marks_user_scope(tmp_path: Path) -> None:
    startup_file = tmp_path / "launch.cmd"
    startup_file.write_bytes(b"@echo off\r\n")

    result = collect_startup_entries(roots=(("user", str(tmp_path)),), environ={})

    assert result.complete
    assert len(result.entries) == 1
    entry = result.entries[0]
    assert entry.exists_on_disk is True
    assert entry.user_writable_path is True
    assert entry.metadata["sha256"] == hashlib.sha256(startup_file.read_bytes()).hexdigest()


def test_startup_collector_distinguishes_missing_and_inaccessible_roots(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    missing_root = tmp_path / "missing"
    denied_root = tmp_path / "denied"
    real_stat = Path.stat

    def deny_selected_root(path: Path, *args: object, **kwargs: object) -> object:
        if path == denied_root:
            raise PermissionError("startup root denied")
        return real_stat(path, *args, **kwargs)

    monkeypatch.setattr(Path, "stat", deny_selected_root)

    result = collect_startup_entries(
        roots=(("user", str(missing_root)), ("machine", str(denied_root))),
        environ={},
    )

    assert result.entries == ()
    assert not result.complete
    assert len(result.diagnostics) == 1
    diagnostic = result.diagnostics[0]
    assert diagnostic.source == "startup_folder"
    assert diagnostic.location == str(denied_root)
    assert diagnostic.message == "startup root denied"


def test_scheduled_task_xml_is_parsed_and_mapped_to_attack(tmp_path: Path) -> None:
    task_xml = """<?xml version="1.0" encoding="UTF-16"?>
    <Task xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
      <Principals><Principal><UserId>alice</UserId></Principal></Principals>
      <Actions Context="Author">
        <Exec>
          <Command>agent.exe</Command>
          <Arguments>--quiet</Arguments>
          <WorkingDirectory>%APPDATA%\\Vendor</WorkingDirectory>
        </Exec>
      </Actions>
    </Task>
    """
    task_file = tmp_path / "Vendor" / "UpdateTask"
    task_file.parent.mkdir()
    task_file.write_bytes(task_xml.encode("utf-16"))

    actions, user_id = parse_scheduled_task_xml(task_file.read_bytes())
    result = collect_scheduled_task_entries(
        task_root=tmp_path,
        environ={"APPDATA": r"C:\Users\alice\AppData\Roaming"},
    )

    assert user_id == "alice"
    assert actions[0].arguments == "--quiet"
    assert result.complete
    assert len(result.entries) == 1
    entry = result.entries[0]
    assert entry.metadata["target_path"] == (r"C:\Users\alice\AppData\Roaming\Vendor\agent.exe")
    assert entry.user_writable_path is True
    finding = evaluate_autorun_entry(entry)
    assert finding is not None
    assert finding.technique_id == "T1053.005"
    assert finding.severity == Severity.HIGH


def test_scheduled_task_root_failures_are_explicit(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    missing_root = tmp_path / "missing"
    file_root = tmp_path / "not-a-directory"
    file_root.write_text("not a task directory", encoding="utf-8")
    denied_root = tmp_path / "denied"
    real_stat = Path.stat

    def deny_selected_root(path: Path, *args: object, **kwargs: object) -> object:
        if path == denied_root:
            raise PermissionError("task root denied")
        return real_stat(path, *args, **kwargs)

    monkeypatch.setattr(Path, "stat", deny_selected_root)

    missing = collect_scheduled_task_entries(task_root=missing_root, environ={})
    not_directory = collect_scheduled_task_entries(task_root=file_root, environ={})
    denied = collect_scheduled_task_entries(task_root=denied_root, environ={})

    assert missing.diagnostics[0].message == "task directory does not exist"
    assert not_directory.diagnostics[0].message == "task root is not a directory"
    assert denied.diagnostics[0].source == "scheduled_task"
    assert denied.diagnostics[0].location == str(denied_root)
    assert denied.diagnostics[0].message == "task root denied"


def test_malformed_task_is_reported_as_incomplete(tmp_path: Path) -> None:
    (tmp_path / "BrokenTask").write_text("<Task>", encoding="utf-8")

    result = collect_scheduled_task_entries(task_root=tmp_path, environ={})

    assert not result.complete
    assert result.entries == ()
    assert result.diagnostics[0].source == "scheduled_task"


def test_unknown_file_and_signature_state_are_not_treated_as_bad() -> None:
    entry = AutorunEntry(
        location=r"HKLM\Software\Microsoft\Windows\CurrentVersion\Run\KnownAgent",
        command=r"C:\Program Files\Vendor\agent.exe",
    )

    assert evaluate_autorun_entry(entry) is None


@pytest.mark.skipif(platform.system().casefold() == "windows", reason="requires non-Windows")
def test_windows_collection_refuses_to_fabricate_non_windows_results() -> None:
    with pytest.raises(UnsupportedPlatformError):
        collect_windows_persistence()
