"""Data models for SBOM Creator."""
from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any
from datetime import datetime, timezone
import uuid

@dataclass
class Checksum:
    """Represents a cryptographic hash / checksum (e.g. SHA256, SHA1)."""
    algorithm: str   # 'SHA256', 'SHA1', etc.
    value: str       # hex digest

@dataclass
class Relationship:
    """Represents a relationship between two elements (e.g. in SPDX / CycloneDX)."""
    spdx_element_id: str           # Source ID (e.g. SPDXRef-DOCUMENT or SPDXRef-Package-root)
    relationship_type: str         # e.g. DESCRIBES, DEPENDS_ON, CONTAINS
    related_spdx_element: str      # Target ID (e.g. SPDXRef-Package-...)
    comment: Optional[str] = None

@dataclass
class Component:
    name: str
    version: str = "unknown"
    component_type: str = "library"  # e.g., 'operating-system', 'library', 'application'
    language: Optional[str] = None   # e.g., 'python', 'go', 'typescript', 'c', 'cpp', 'csharp', 'java'
    purl: Optional[str] = None       # Package URL if applicable
    license: Optional[str] = None
    description: Optional[str] = None
    properties: Dict[str, Any] = field(default_factory=dict)
    spdx_id: Optional[str] = None    # Custom SPDX identifier if specified
    bom_ref: Optional[str] = None    # CycloneDX BOM reference key
    cpe: Optional[str] = None        # CPE 2.3 string (e.g. cpe:2.3:a:vendor:product:version:...)
    checksums: List[Checksum] = field(default_factory=list)

@dataclass
class SBOMMetadata:
    tool_name: str = "sbom-creator"
    tool_version: str = "0.1.0"
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    target_name: str = "target"
    target_version: str = "latest"
    description: Optional[str] = None
    license: Optional[str] = None
    copyright_text: Optional[str] = "NOASSERTION"
    creator: Optional[str] = None
    supplier: Optional[str] = None
    download_location: Optional[str] = "NOASSERTION"
    homepage: Optional[str] = None
    data_license: str = "CC0-1.0"
    namespace_prefix: str = "https://spdx.org/spdxdocs"
    document_namespace: Optional[str] = None
    serial_number: str = field(default_factory=lambda: f"urn:uuid:{uuid.uuid4()}")
    root_checksums: List[Checksum] = field(default_factory=list)

@dataclass
class SBOMDocument:
    metadata: SBOMMetadata
    components: List[Component] = field(default_factory=list)
    relationships: List[Relationship] = field(default_factory=list)
