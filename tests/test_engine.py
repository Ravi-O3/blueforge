from blueforge.collectors import SampleCollector
from blueforge.detections.engine import DetectionEngine, load_rules
from blueforge.normalizer import normalize_many


def _matches(sysmon_log, sigma_dir):
    events = list(normalize_many(SampleCollector(sysmon_log).collect()))
    engine = DetectionEngine(load_rules(sigma_dir))
    return [m for e in events for m in engine.evaluate(e)]


def test_rules_load(sigma_dir):
    rules = load_rules(sigma_dir)
    assert len(rules) >= 4
    assert all(r.mitre for r in rules)  # every rule is MITRE-mapped


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
