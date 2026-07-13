"""Collectors read a raw log source and hand raw dicts to the normalizer.

WHY separate collectors from normalization: the JOB of a collector is only to
*acquire* data (read a file, call the Wazuh API, tail syslog). Turning that data
into the common schema is a different job (normalizer). Keeping them apart means
adding a new log source never touches detection code.

Current: `SampleCollector` reads JSON Lines files (used by tests and demos).
Planned: `EvtxCollector` (python-evtx), `SyslogCollector`, `WazuhApiCollector`.
Each will expose the same `.collect()` method returning raw dicts.
"""

from blueforge.collectors.sample import SampleCollector

__all__ = ["SampleCollector"]
