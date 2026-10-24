"""Formatters package and factory."""
from typing import Dict, Type
from sbom_creator.formats.base import BaseFormatter
from sbom_creator.formats.cyclonedx import CycloneDXFormatter
from sbom_creator.formats.spdx import SPDXFormatter
from sbom_creator.formats.simple import SimpleJSONFormatter, CSVFormatter

FORMATTERS: Dict[str, Type[BaseFormatter]] = {
    "cyclonedx": CycloneDXFormatter,
    "cyclonedx-json": CycloneDXFormatter,
    "spdx": SPDXFormatter,
    "spdx-json": SPDXFormatter,
    "json": SimpleJSONFormatter,
    "csv": CSVFormatter,
}

def get_formatter(format_name: str) -> BaseFormatter:
    """Return an instance of the formatter matching the given format name."""
    fmt = format_name.lower().strip()
    if fmt not in FORMATTERS:
        valid_options = ", ".join(sorted(set(FORMATTERS.keys())))
        raise ValueError(f"Unsupported format '{format_name}'. Available formats: {valid_options}")
    return FORMATTERS[fmt]()
