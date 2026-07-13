"""BlueForge command line interface.

The CLI is the glue: it wires collector -> normalizer -> detection engine ->
report. Everything it does can be traced through one file, which is exactly what
you want when explaining the project in an interview.

Commands:
    blueforge detect --logs examples/sample_sysmon.jsonl --rules detections/sigma
    blueforge normalize --logs examples/sample_sysmon.jsonl
    blueforge iocs --text "powershell -enc ... 45.77.12.9 evil.com"
"""

from __future__ import annotations

import click
from rich.console import Console
from rich.table import Table

from blueforge import __version__
from blueforge.collectors import SampleCollector
from blueforge.config import load_config
from blueforge.detections.engine import DetectionEngine, load_rules
from blueforge.enrichment.ioc import extract_iocs
from blueforge.logging_config import setup_logging
from blueforge.normalizer import normalize_many
from blueforge.reporting import build_report
from blueforge.utils.io import write_text

console = Console()


@click.group()
@click.version_option(__version__, prog_name="blueforge")
def main() -> None:
    """BlueForge: turn logs into detections, alerts, and reports."""
    setup_logging(load_config().log_level)


@main.command()
@click.option("--logs", required=True, help="Path to a JSON Lines log file.")
@click.option("--rules", default="detections/sigma", help="Directory of Sigma-style rules.")
@click.option(
    "--report", "report_path", default=None, help="Optional path to write a Markdown report."
)
def detect(logs: str, rules: str, report_path: str | None) -> None:
    """Run detections over a log file and print what fired."""
    events = list(normalize_many(SampleCollector(logs).collect()))
    engine = DetectionEngine(load_rules(rules))
    matches = [m for e in events for m in engine.evaluate(e)]

    table = Table(title=f"Detections ({len(matches)} fired over {len(events)} events)")
    table.add_column("Rule")
    table.add_column("Severity")
    table.add_column("MITRE")
    table.add_column("Host")
    for m in matches:
        table.add_row(
            m.detection.title,
            m.detection.level,
            ", ".join(m.detection.mitre),
            m.event.host or "n/a",
        )
    console.print(table)

    if report_path:
        out = write_text(report_path, build_report(matches))
        console.print(f"[green]Report written to {out}[/green]")


@main.command()
@click.option("--logs", required=True, help="Path to a JSON Lines log file.")
def normalize(logs: str) -> None:
    """Show raw logs normalized into the common Event schema."""
    for event in normalize_many(SampleCollector(logs).collect()):
        console.print(event.model_dump(exclude={"raw"}, exclude_none=True))


@main.command()
@click.option("--text", required=True, help="Text to extract IOCs from.")
def iocs(text: str) -> None:
    """Extract IOCs (IPs, domains, URLs, hashes) from arbitrary text."""
    console.print(extract_iocs(text))


if __name__ == "__main__":
    main()
