"""SPDX JSON Formatter (spec version 2.3) with full Relationships, Checksums, and Custom Metadata support."""
import json
import re
from typing import Dict, Any, List
from sbom_creator.models import SBOMDocument
from sbom_creator.formats.base import BaseFormatter

class SPDXFormatter(BaseFormatter):
    """Formats an SBOMDocument into SPDX v2.3 JSON representation."""

    def format(self, doc: SBOMDocument) -> str:
        ns_prefix = doc.metadata.namespace_prefix.rstrip("/")
        doc_ns = f"{ns_prefix}/{doc.metadata.target_name}-{doc.metadata.serial_number.replace('urn:uuid:', '')}"
        
        # Prepare Root Package ID
        root_safe_name = re.sub(r"[^a-zA-Z0-9.\-]", "-", doc.metadata.target_name).strip("-") or "root"
        root_spdx_id = f"SPDXRef-Package-{root_safe_name}-root"

        # Creators list
        creators = [f"Tool: {doc.metadata.tool_name}-{doc.metadata.tool_version}"]
        if doc.metadata.creator:
            creators.append(doc.metadata.creator)

        data: Dict[str, Any] = {
            "spdxVersion": "SPDX-2.3",
            "dataLicense": doc.metadata.data_license,
            "SPDXID": "SPDXRef-DOCUMENT",
            "name": doc.metadata.target_name,
            "documentNamespace": doc_ns,
            "creationInfo": {
                "created": doc.metadata.timestamp,
                "creators": creators
            },
            "packages": [],
            "relationships": []
        }

        # 1. Add Root Application Package
        root_pkg: Dict[str, Any] = {
            "SPDXID": root_spdx_id,
            "name": doc.metadata.target_name,
            "versionInfo": doc.metadata.target_version,
            "downloadLocation": doc.metadata.download_location,
            "filesAnalyzed": False,
            "licenseConcluded": doc.metadata.license or "NOASSERTION",
            "licenseDeclared": doc.metadata.license or "NOASSERTION",
            "copyrightText": doc.metadata.copyright_text or "NOASSERTION",
            "primaryPackagePurpose": "APPLICATION"
        }
        if doc.metadata.description:
            root_pkg["description"] = doc.metadata.description
        if doc.metadata.supplier:
            root_pkg["supplier"] = doc.metadata.supplier
        if doc.metadata.homepage:
            root_pkg["homepage"] = doc.metadata.homepage

        if doc.metadata.root_checksums:
            root_pkg["checksums"] = [
                {
                    "algorithm": cs.algorithm,
                    "checksumValue": cs.value
                }
                for cs in doc.metadata.root_checksums
            ]
        data["packages"].append(root_pkg)

        # Document describes the root package
        data["relationships"].append({
            "spdxElementId": "SPDXRef-DOCUMENT",
            "relationshipType": "DESCRIBES",
            "relatedSpdxElement": root_spdx_id
        })

        # 2. Add Component Packages
        pkg_spdx_ids: List[str] = []
        for idx, comp in enumerate(doc.components, start=1):
            safe_name = re.sub(r"[^a-zA-Z0-9.\-]", "-", comp.name).strip("-") or f"component-{idx}"
            spdx_id = comp.spdx_id or f"SPDXRef-Package-{safe_name}-{idx}"
            comp.spdx_id = spdx_id
            pkg_spdx_ids.append(spdx_id)

            pkg: Dict[str, Any] = {
                "SPDXID": spdx_id,
                "name": comp.name,
                "versionInfo": comp.version if comp.version else "NOASSERTION",
                "downloadLocation": "NOASSERTION",
                "filesAnalyzed": False,
                "licenseConcluded": comp.license or "NOASSERTION",
                "licenseDeclared": comp.license or "NOASSERTION",
                "copyrightText": "NOASSERTION"
            }
            if comp.description:
                pkg["description"] = comp.description
            if comp.checksums:
                pkg["checksums"] = [
                    {
                        "algorithm": cs.algorithm,
                        "checksumValue": cs.value
                    }
                    for cs in comp.checksums
                ]
            external_refs = []
            if comp.purl:
                external_refs.append({
                    "referenceCategory": "PACKAGE-MANAGER",
                    "referenceType": "purl",
                    "referenceLocator": comp.purl
                })
            if comp.cpe:
                external_refs.append({
                    "referenceCategory": "SECURITY",
                    "referenceType": "cpe23Type",
                    "referenceLocator": comp.cpe
                })
            if external_refs:
                pkg["externalRefs"] = external_refs

            data["packages"].append(pkg)

        # 3. Add Relationships
        if doc.relationships:
            for rel in doc.relationships:
                rel_item = {
                    "spdxElementId": rel.spdx_element_id,
                    "relationshipType": rel.relationship_type,
                    "relatedSpdxElement": rel.related_spdx_element
                }
                if rel.comment:
                    rel_item["comment"] = rel.comment
                data["relationships"].append(rel_item)
        else:
            # Default dependency relationships: root package DEPENDS_ON each component
            for pkg_id in pkg_spdx_ids:
                data["relationships"].append({
                    "spdxElementId": root_spdx_id,
                    "relationshipType": "DEPENDS_ON",
                    "relatedSpdxElement": pkg_id
                })

        return json.dumps(data, indent=2, ensure_ascii=False)
