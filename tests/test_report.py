from blueforge.collectors import SampleCollector
from blueforge.detections.engine import DetectionEngine, load_rules
from blueforge.normalizer import normalize_many
from blueforge.reporting import build_report


def test_report_contains_findings(sysmon_log, sigma_dir):
    events = list(normalize_many(SampleCollector(sysmon_log).collect()))
    engine = DetectionEngine(load_rules(sigma_dir))
    matches = [m for e in events for m in engine.evaluate(e)]
    report = build_report(matches, title="Test triage")
    assert "# Incident Report" in report
    assert "MITRE ATT&CK" in report
    assert "bf-0001" in report
