"""CycloneDX JSON Formatter (spec version 1.5) with dependencies support."""
import json
from typing import Dict, Any, List
from sbom_creator.models import SBOMDocument
from sbom_creator.formats.base import BaseFormatter

class CycloneDXFormatter(BaseFormatter):
    """Formats an SBOMDocument into CycloneDX v1.5 JSON representation with dependencies."""

    def format(self, doc: SBOMDocument) -> str:
        root_bom_ref = f"{doc.metadata.target_name}-root"

        data: Dict[str, Any] = {
            "$schema": "http://cyclonedx.org/schema/bom-1.5.json",
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "serialNumber": doc.metadata.serial_number,
            "version": 1,
            "metadata": {
                "timestamp": doc.metadata.timestamp,
                "tools": [
                    {
                        "vendor": "sbom-creator",
                        "name": doc.metadata.tool_name,
                        "version": doc.metadata.tool_version
                    }
                ],
                "component": {
                    "type": "application",
                    "bom-ref": root_bom_ref,
                    "name": doc.metadata.target_name,
                    "version": doc.metadata.target_version
                }
            },
            "components": [],
            "dependencies": []
        }

        # Add optional metadata attributes
        root_comp = data["metadata"]["component"]
        if doc.metadata.description:
            root_comp["description"] = doc.metadata.description
        if doc.metadata.license:
            root_comp["licenses"] = [{"license": {"id": doc.metadata.license}}]
        if doc.metadata.supplier:
            root_comp["supplier"] = {"name": doc.metadata.supplier}
        if doc.metadata.creator:
            root_comp["author"] = doc.metadata.creator

        comp_refs: List[str] = []

        for idx, comp in enumerate(doc.components, start=1):
            bom_ref = comp.bom_ref or comp.purl or f"{comp.name}@{comp.version}-{idx}"
            comp.bom_ref = bom_ref
            comp_refs.append(bom_ref)

            item: Dict[str, Any] = {
                "type": comp.component_type or "library",
                "bom-ref": bom_ref,
                "name": comp.name,
                "version": comp.version
            }
            if comp.purl:
                item["purl"] = comp.purl
            if comp.cpe:
                item["cpe"] = comp.cpe
            if comp.description:
                item["description"] = comp.description
            if comp.license:
                item["licenses"] = [{"license": {"id": comp.license}}]
            if comp.checksums:
                item["hashes"] = [
                    {
                        "alg": f"{cs.algorithm[:3]}-{cs.algorithm[3:]}" if cs.algorithm.startswith("SHA") else cs.algorithm,
                        "content": cs.value
                    }
                    for cs in comp.checksums
                ]

            # Properties
            props = []
            if comp.language:
                props.append({"name": "language", "value": comp.language})
            for k, v in comp.properties.items():
                props.append({"name": k, "value": str(v)})
            if props:
                item["properties"] = props

            data["components"].append(item)

        # Build dependencies section
        if comp_refs:
            data["dependencies"].append({
                "ref": root_bom_ref,
                "dependsOn": comp_refs
            })

        return json.dumps(data, indent=2, ensure_ascii=False)
