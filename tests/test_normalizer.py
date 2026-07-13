"""The normalizer is the contract of the whole platform, so test it carefully."""

from blueforge.normalizer import normalize
from blueforge.schema import EventCategory


def test_sysmon_process_mapping():
    raw = {
        "_source": "sysmon",
        "EventID": 1,
        "UtcTime": "2026-07-12T14:05:33",
        "Computer": "WKSTN-07",
        "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "CommandLine": "powershell.exe -enc ABC",
        "ParentImage": "C:\\Windows\\System32\\cmd.exe",
    }
    e = normalize(raw)
    assert e.category == EventCategory.PROCESS
    assert e.process.endswith("powershell.exe")
    assert "-enc" in e.command_line
    assert e.host == "WKSTN-07"


def test_windows_failed_logon_is_authentication():
    e = normalize({"_source": "windows", "EventID": 4625, "IpAddress": "185.220.101.4"})
    assert e.category == EventCategory.AUTHENTICATION
    assert e.src_ip == "185.220.101.4"


def test_unknown_source_preserved_in_raw():
    e = normalize({"_source": "mystery", "foo": "bar"})
    assert e.raw["foo"] == "bar"
