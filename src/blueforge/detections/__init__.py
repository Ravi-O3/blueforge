"""The detection engine: loads rules and matches them against normalized events."""

from blueforge.detections.engine import Detection, DetectionEngine, load_rules

__all__ = ["DetectionEngine", "Detection", "load_rules"]
