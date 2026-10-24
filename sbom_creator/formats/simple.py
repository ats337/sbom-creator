"""Simple JSON and CSV formatters."""
import json
import csv
import io
from typing import Dict, Any
from sbom_creator.models import SBOMDocument
from sbom_creator.formats.base import BaseFormatter

class SimpleJSONFormatter(BaseFormatter):
    """Formats an SBOMDocument into human-readable custom JSON."""

    def format(self, doc: SBOMDocument) -> str:
        data: Dict[str, Any] = {
            "metadata": {
                "tool": f"{doc.metadata.tool_name} v{doc.metadata.tool_version}",
                "generatedAt": doc.metadata.timestamp,
                "target": doc.metadata.target_name,
                "totalComponents": len(doc.components)
            },
            "components": [
                {
                    "name": c.name,
                    "version": c.version,
                    "type": c.component_type,
                    "language": c.language,
                    "purl": c.purl,
                    "license": c.license,
                    "description": c.description,
                    "properties": c.properties
                }
                for c in doc.components
            ]
        }
        return json.dumps(data, indent=2, ensure_ascii=False)

class CSVFormatter(BaseFormatter):
    """Formats an SBOMDocument into CSV."""

    def format(self, doc: SBOMDocument) -> str:
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(["Name", "Version", "Type", "Language", "PURL", "License", "Manifest/Source"])

        for c in doc.components:
            manifest = c.properties.get("manifest", c.properties.get("package_manager", ""))
            writer.writerow([
                c.name,
                c.version,
                c.component_type,
                c.language or "",
                c.purl or "",
                c.license or "",
                manifest
            ])

        return output.getvalue()
