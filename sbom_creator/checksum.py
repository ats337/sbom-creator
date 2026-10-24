"""Utilities for computing cryptographic checksums for files and components."""
import hashlib
from pathlib import Path
from typing import List, Union
from sbom_creator.models import Checksum

def compute_file_checksums(file_path: Union[str, Path]) -> List[Checksum]:
    """Compute SHA256 and SHA1 checksums for a given file."""
    p = Path(file_path).resolve()
    if not p.is_file():
        return []

    try:
        sha256 = hashlib.sha256()
        sha1 = hashlib.sha1()

        with open(p, "rb") as f:
            while chunk := f.read(65536):
                sha256.update(chunk)
                sha1.update(chunk)

        return [
            Checksum(algorithm="SHA256", value=sha256.hexdigest()),
            Checksum(algorithm="SHA1", value=sha1.hexdigest())
        ]
    except Exception:
        return []

def compute_content_checksums(content: bytes) -> List[Checksum]:
    """Compute SHA256 and SHA1 checksums for raw bytes."""
    return [
        Checksum(algorithm="SHA256", value=hashlib.sha256(content).hexdigest()),
        Checksum(algorithm="SHA1", value=hashlib.sha1(content).hexdigest())
    ]
