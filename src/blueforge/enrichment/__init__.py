"""Turn a raw alert into something an analyst can act on: extract IOCs, look them up."""

from blueforge.enrichment.ioc import extract_iocs

__all__ = ["extract_iocs"]
