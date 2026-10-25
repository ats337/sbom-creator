"""Resolvers for inferring missing component versions, licenses, and applying user overrides."""
import re
import shutil
import subprocess
from pathlib import Path
from typing import Dict, Any, Optional, List
import importlib.metadata

from sbom_creator.models import Component, Checksum
from sbom_creator.cpe import resolve_cpe23
from sbom_creator.checksum import compute_file_checksums
from sbom_creator.artifact import find_package_artifact

# Known SPDX licenses for common OSS libraries
KNOWN_LICENSES: Dict[str, str] = {
    # Networking / Transfer
    "curl": "curl",
    "libcurl": "curl",
    # Imaging / OCR / Documents
    "lept": "BSD-2-Clause",
    "leptonica": "BSD-2-Clause",
    "liblept": "BSD-2-Clause",
    "tesseract": "Apache-2.0",
    "libtesseract": "Apache-2.0",
    "libarchive": "BSD-2-Clause",
    "archive": "BSD-2-Clause",
    "png": "Libpng",
    "libpng": "Libpng",
    "jpeg": "IJG",
    "libjpeg": "IJG",
    "tiff": "libtiff",
    "libtiff": "libtiff",
    "webp": "BSD-3-Clause",
    "libwebp": "BSD-3-Clause",
    "opencv": "Apache-2.0",
    "cairo": "LGPL-2.1-or-later OR MPL-1.1",
    "freetype": "FTL OR GPL-2.0-or-later",
    "freetype2": "FTL OR GPL-2.0-or-later",
    "harfbuzz": "Old-MIT",
    "pango": "LGPL-2.0-or-later",
    # Unicode / Text
    "icu": "ICU",
    "icu-uc": "ICU",
    "icu-i18n": "ICU",
    "icu-io": "ICU",
    # Crypto / Security
    "openssl": "Apache-2.0",
    "libssl": "Apache-2.0",
    "libcrypto": "Apache-2.0",
    # Compression
    "zlib": "Zlib",
    "z": "Zlib",
    "libz": "Zlib",
    "bzip2": "bzip2-1.0.6",
    "libbz2": "bzip2-1.0.6",
    "xz": "0BSD OR Public-Domain",
    "liblzma": "0BSD OR Public-Domain",
    "zstd": "BSD-3-Clause OR GPL-2.0-only",
    "libzstd": "BSD-3-Clause OR GPL-2.0-only",
    # Database
    "sqlite": "blessing",
    "sqlite3": "blessing",
    "libsqlite3": "blessing",
    # XML / JSON / Parsing
    "libxml2": "MIT",
    "xml2": "MIT",
    "expat": "MIT",
    "libexpat": "MIT",
    "nlohmann-json": "MIT",
    "json-c": "MIT",
    # Utilities / Runtime
    "glib": "LGPL-2.1-or-later",
    "glib-2.0": "LGPL-2.1-or-later",
    "boost": "BSL-1.0",
    "libuv": "MIT",
    "uv": "MIT",
    "protobuf": "BSD-3-Clause",
    "pcre": "BSD-3-Clause",
    "pcre2": "BSD-3-Clause",
    "pcre2-8": "BSD-3-Clause",
    "fmt": "MIT",
    "spdlog": "MIT",
    "gtest": "BSD-3-Clause",
    "googletest": "BSD-3-Clause",
}

COMMON_HEADER_SEARCH_PATHS = [
    "/usr/include",
    "/usr/local/include",
    "/opt/homebrew/include",
    "/opt/local/include"
]

def query_pkg_config_version(pkg_name: str) -> Optional[str]:
    """Query pkg-config --modversion for a given library name."""
    if not shutil.which("pkg-config"):
        return None

    clean_name = pkg_name.strip()
    candidates = [clean_name]
    if clean_name.startswith("lib"):
        candidates.append(clean_name[3:])
    else:
        candidates.append(f"lib{clean_name}")

    for cand in candidates:
        try:
            out = subprocess.check_output(
                ["pkg-config", "--modversion", cand],
                text=True, stderr=subprocess.DEVNULL, timeout=2
            ).strip()
            if out and not out.startswith("Package") and not "\n" in out:
                return out
        except Exception:
            continue

    return None

def find_system_header_version(lib_name: str) -> Optional[str]:
    """Scan system include directories for common version macros."""
    clean = lib_name.lower().removeprefix("lib")
    
    # Target files to look for
    header_targets = {
        "z": ("zlib.h", r'#\s*define\s+ZLIB_VERSION\s+"([^"]+)"'),
        "zlib": ("zlib.h", r'#\s*define\s+ZLIB_VERSION\s+"([^"]+)"'),
        "curl": ("curl/curlver.h", r'#\s*define\s+LIBCURL_VERSION\s+"([^"]+)"'),
        "sqlite": ("sqlite3.h", r'#\s*define\s+SQLITE_VERSION\s+"([^"]+)"'),
        "sqlite3": ("sqlite3.h", r'#\s*define\s+SQLITE_VERSION\s+"([^"]+)"'),
        "openssl": ("openssl/opensslv.h", r'#\s*define\s+OPENSSL_VERSION_TEXT\s+"OpenSSL\s+([0-9\.]+[^"]*)"'),
        "png": ("png.h", r'#\s*define\s+PNG_LIBPNG_VER_STRING\s+"([^"]+)"'),
        "tiff": ("tiffvers.h", r'#\s*define\s+TIFFLIB_VERSION_STR\s+"LIBTIFF,\s+Version\s+([0-9\.]+[^"]*)"'),
    }

    if clean in header_targets:
        rel_header, pattern = header_targets[clean]
        for base in COMMON_HEADER_SEARCH_PATHS:
            header_file = Path(base) / rel_header
            if header_file.is_file():
                try:
                    with open(header_file, "r", encoding="utf-8", errors="ignore") as f:
                        for line in f:
                            m = re.search(pattern, line)
                            if m:
                                return m.group(1).strip()
                except Exception:
                    pass

    return None

def enrich_components(components: List[Component], overrides: Optional[Dict[str, Any]] = None, project_dir: Optional[Path] = None) -> None:
    """Enrich components with missing versions, licenses, and apply user overrides."""
    overrides_dict = overrides or {}

    for comp in components:
        # 1. Apply user overrides from config if specified (highest priority)
        override = overrides_dict.get(comp.name) or overrides_dict.get(comp.name.lower())
        if override:
            if "version" in override and override["version"]:
                comp.version = str(override["version"])
                comp.properties["version_source"] = "config_override"
            if "license" in override and override["license"]:
                comp.license = str(override["license"])
                comp.properties["license_source"] = "config_override"
            if "cpe" in override and override["cpe"]:
                comp.cpe = str(override["cpe"])
            if "description" in override and override["description"]:
                comp.description = str(override["description"])
            if "package_file_name" in override and override["package_file_name"]:
                comp.properties["artifact_file"] = str(override["package_file_name"])
            elif "packageFileName" in override and override["packageFileName"]:
                comp.properties["artifact_file"] = str(override["packageFileName"])

        # 2. Infer version if unknown
        if not comp.version or comp.version.lower() == "unknown":
            # 2a. Query pkg-config for C/C++ libraries
            if comp.language in ("c/cpp", "c", "cpp") or not comp.language:
                ver = query_pkg_config_version(comp.name)
                if ver:
                    comp.version = ver
                    comp.properties["version_source"] = "pkg-config"
                else:
                    # 2b. Query system headers
                    hdr_ver = find_system_header_version(comp.name)
                    if hdr_ver:
                        comp.version = hdr_ver
                        comp.properties["version_source"] = "system_header"

            # 2c. Query Python environment
            elif comp.language == "python":
                try:
                    py_ver = importlib.metadata.version(comp.name)
                    if py_ver:
                        comp.version = py_ver
                        comp.properties["version_source"] = "python_environment"
                except Exception:
                    pass

            # 2d. Query Node.js node_modules if project_dir is provided
            elif comp.language == "typescript" and project_dir:
                nm_pkg = project_dir / "node_modules" / comp.name / "package.json"
                if nm_pkg.is_file():
                    try:
                        import json
                        with open(nm_pkg, "r", encoding="utf-8") as nf:
                            nm_data = json.load(nf)
                            if "version" in nm_data:
                                comp.version = nm_data["version"]
                                comp.properties["version_source"] = "node_modules"
                            if not comp.license and "license" in nm_data:
                                comp.license = nm_data["license"]
                                comp.properties["license_source"] = "node_modules"
                    except Exception:
                        pass

        # 3. Infer license if missing
        if not comp.license:
            clean_name = comp.name.lower().strip()
            lookup_key = clean_name.removesuffix("-devel").removesuffix("-dev")
            matched_lic = KNOWN_LICENSES.get(lookup_key)
            if not matched_lic and lookup_key.startswith("lib"):
                matched_lic = KNOWN_LICENSES.get(lookup_key[3:])

            if matched_lic:
                comp.license = matched_lic
                comp.properties["license_source"] = "known_oss_preset"
            elif comp.language == "python":
                try:
                    meta = importlib.metadata.metadata(comp.name)
                    lic = meta.get("License")
                    if lic and lic.lower() != "unknown":
                        comp.license = lic
                        comp.properties["license_source"] = "python_metadata"
                except Exception:
                    pass

        # 4. Synchronize PURL and CPE with updated version
        if comp.version and comp.version.lower() != "unknown":
            # Update PURL version if PURL exists
            if comp.purl and "@" not in comp.purl:
                comp.purl = f"{comp.purl}@{comp.version}"
            elif comp.purl and "@" in comp.purl:
                base_purl = comp.purl.split("@")[0]
                comp.purl = f"{base_purl}@{comp.version}"

            # Update CPE version
            comp.cpe = resolve_cpe23(comp.name, comp.version)

        # 5. Locate authentic package artifact and compute true artifact checksums
        # 5a. If specified in config override (highest priority)
        if override:
            if "sha256" in override and override["sha256"]:
                comp.checksums = [Checksum(algorithm="SHA256", value=str(override["sha256"]))]
                if "sha1" in override and override["sha1"]:
                    comp.checksums.append(Checksum(algorithm="SHA1", value=str(override["sha1"])))
                comp.properties["checksum_source"] = "config_override"
            elif "checksums" in override and isinstance(override["checksums"], list):
                comp.checksums = [
                    Checksum(algorithm=cs.get("algorithm", "SHA256"), value=cs.get("checksumValue", cs.get("value", "")))
                    for cs in override["checksums"] if isinstance(cs, dict)
                ]
                comp.properties["checksum_source"] = "config_override"

        # 5b. If not yet set, attempt to locate physical library/binary artifact on disk
        if not comp.checksums:
            artifact_path = find_package_artifact(comp, project_dir=project_dir)
            if artifact_path and artifact_path.is_file():
                art_cs = compute_file_checksums(artifact_path)
                if art_cs:
                    comp.checksums = art_cs
                    comp.properties["artifact_file"] = str(artifact_path)
                    comp.properties["checksum_source"] = "local_artifact"
