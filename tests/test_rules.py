from persistence_scanner import (
    AutorunEntry,
    Severity,
    evaluate_autorun_entry,
    find_persistence_risks,
)


def test_run_key_with_user_writable_unsigned_binary_is_high_risk() -> None:
    finding = evaluate_autorun_entry(
        AutorunEntry(
            location=r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run\BadEntry",
            command=r"C:\Users\alice\AppData\Roaming\bad.exe",
            scope="user",
            signed=False,
            user_writable_path=True,
        )
    )

    assert finding is not None
    assert finding.technique_id == "T1547.001"
    assert finding.severity == Severity.HIGH
    assert "user-writable path" in finding.rationale


def test_clean_signed_service_is_not_flagged() -> None:
    finding = evaluate_autorun_entry(
        AutorunEntry(
            location=r"HKLM\System\CurrentControlSet\Services\W32Time",
            command=r"C:\Windows\System32\svchost.exe -k LocalService",
            signed=True,
            exists_on_disk=True,
            user_writable_path=False,
        )
    )

    assert finding is None


def test_missing_startup_entry_is_flagged_and_sorted() -> None:
    findings = find_persistence_risks(
        [
            AutorunEntry(
                location=r"Startup\OneDrive.lnk",
                command=r"C:\Users\alice\AppData\Roaming\OneDrive.exe",
                exists_on_disk=False,
                signed=True,
                user_writable_path=True,
            ),
            AutorunEntry(
                location=r"HKLM\System\CurrentControlSet\Services\Spooler",
                command=r"C:\Windows\System32\spoolsv.exe",
                signed=True,
            ),
        ]
    )

    assert len(findings) == 1
    assert findings[0].technique_id == "T1547.001"
    assert findings[0].severity == Severity.HIGH
    assert findings[0].evidence == (r"C:\Users\alice\AppData\Roaming\OneDrive.exe",)
