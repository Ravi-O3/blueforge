"""BlueForge: Detection Engineering and SOC Automation Platform.

The package is organized as a simple pipeline that mirrors a real SOC:

    collectors -> normalizer -> detections -> enrichment -> reporting / hunting

Each subpackage has ONE job so the whole thing stays easy to explain.
"""

__version__ = "0.1.0"
