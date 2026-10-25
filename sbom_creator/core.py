"""Core orchestration logic for generating SBOMs."""
import os
from pathlib import Path
from typing import List, Dict, Any, Optional

from sbom_creator.models import SBOMDocument, SBOMMetadata, Component
from sbom_creator.scanners.os_scanner import OSScanner
from sbom_creator.scanners.project_scanner import ProjectScanner
from sbom_creator.formats import get_formatter
from sbom_creator.checksum import compute_file_checksums, compute_content_checksums
from sbom_creator.cpe import resolve_cpe23
from sbom_creator.resolver import enrich_components

def generate_sbom(
    target_path: str = ".",
    target_name: str = "",
    include_os: bool = False,
    os_only: bool = False,
    scan_os_packages: bool = True,
    format_name: str = "cyclonedx",
    settings: Optional[Dict[str, Any]] = None
) -> str:
    """Scan targets and return formatted SBOM string based on resolved settings."""
    cfg = settings or {}

    effective_target = cfg.get("target") or target_path
    target_dir = Path(effective_target).resolve()
    
    effective_name = cfg.get("name") or target_name or target_dir.name or "system"
    effective_format = cfg.get("format") or format_name or "cyclonedx"
    effective_include_os = cfg.get("include_os", include_os)
    effective_os_only = cfg.get("os_only", os_only)
    effective_scan_os_packages = cfg.get("scan_os_packages", scan_os_packages)

    # Initialize Metadata with configurable attributes
    metadata = SBOMMetadata(
        target_name=effective_name,
        target_version=cfg.get("version") or "latest",
        description=cfg.get("description"),
        license=cfg.get("license"),
        copyright_text=cfg.get("copyright") or "NOASSERTION",
        creator=cfg.get("creator"),
        supplier=cfg.get("supplier"),
        download_location=cfg.get("download_location") or "NOASSERTION",
        homepage=cfg.get("homepage"),
        tool_name=cfg.get("tool_name") or "sbom-creator",
        tool_version=cfg.get("tool_version") or "0.1.0",
        data_license="CC0-1.0",
        namespace_prefix=cfg.get("namespace_prefix") or "https://spdx.org/spdxdocs",
        document_namespace=cfg.get("document_namespace")
    )
    if cfg.get("serial_number"):
        metadata.serial_number = cfg["serial_number"]

    components: List[Component] = []

    # Calculate root package checksum if target exists
    if target_dir.exists():
        if target_dir.is_file():
            metadata.root_checksums = compute_file_checksums(target_dir)
        elif target_dir.is_dir():
            common_descriptors = [
                "CMakeLists.txt", "Makefile", "package.json", "pom.xml",
                "go.mod", "pyproject.toml", "requirements.txt", "vcpkg.json"
            ]
            for desc in common_descriptors:
                p = target_dir / desc
                if p.is_file():
                    metadata.root_checksums = compute_file_checksums(p)
                    break
            if not metadata.root_checksums:
                metadata.root_checksums = compute_content_checksums(str(target_dir).encode("utf-8"))

    # 1. OS Scanning
    if effective_include_os or effective_os_only:
        os_scanner = OSScanner(scan_packages=effective_scan_os_packages)
        components.extend(os_scanner.scan())

    # 2. Project Scanning
    if not effective_os_only and target_dir.exists():
        project_scanner = ProjectScanner(root_dir=str(target_dir))
        components.extend(project_scanner.scan())

    # Enrich components with missing versions, licenses, and apply config overrides
    component_overrides = cfg.get("component_overrides") or {}
    enrich_components(components, overrides=component_overrides, project_dir=target_dir if target_dir.exists() else None)

    doc = SBOMDocument(metadata=metadata, components=components)
    formatter = get_formatter(effective_format)
    return formatter.format(doc)
