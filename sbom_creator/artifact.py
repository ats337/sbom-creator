"""Artifact resolver for locating actual compiled binary/library files to compute true package checksums."""
import os
import glob
import shutil
import subprocess
from pathlib import Path
from typing import Optional, List
from sbom_creator.models import Component

LIB_EXTENSIONS = [".dylib", ".so", ".a", ".dll", ".lib", ".jar", ".whl"]

def find_package_artifact(comp: Component, project_dir: Optional[Path] = None) -> Optional[Path]:
    """
    Locate the actual physical artifact (binary, shared/static library, archive)
    for a given component to allow computing authentic package checksums.
    """
    clean_name = comp.name.lower().strip()
    # Normalize name candidates (e.g. 'libcurl' and 'curl')
    name_candidates = [clean_name]
    if clean_name.startswith("lib"):
        name_candidates.append(clean_name[3:])
    else:
        name_candidates.append(f"lib{clean_name}")

    # 1. Project-local directories (vendored libraries, built outputs, third_party)
    if project_dir and project_dir.is_dir():
        search_subdirs = ["lib", "libs", "build", "vendor", "third_party", "3rdparty", "deps", "external"]
        for sub in search_subdirs:
            cand_dir = project_dir / sub
            if cand_dir.is_dir():
                for root, _, files in os.walk(cand_dir):
                    for f in files:
                        p = Path(root, f)
                        if p.suffix.lower() in LIB_EXTENSIONS:
                            file_stem = p.stem.lower()
                            if any(cand == file_stem or file_stem.startswith(f"{cand}.") or file_stem.startswith(f"{cand}-") for cand in name_candidates):
                                return p

    # 2. Component properties already pointing to local paths (e.g. macOS app, homebrew source)
    app_path = comp.properties.get("app_path")
    if app_path and Path(app_path).is_dir():
        # For .app, find the main executable
        macos_dir = Path(app_path) / "Contents" / "MacOS"
        if macos_dir.is_dir():
            execs = [p for p in macos_dir.iterdir() if p.is_file() and not p.name.startswith(".")]
            if execs:
                return execs[0]

    source_dir = comp.properties.get("source_dir")
    if source_dir and Path(source_dir).is_dir():
        src_p = Path(source_dir)
        # Search for .dylib / .so / .a or binary
        lib_dir = src_p / "lib"
        if lib_dir.is_dir():
            libs = [p for p in lib_dir.glob("*") if p.is_file() and p.suffix.lower() in LIB_EXTENSIONS]
            if libs:
                return libs[0]
        bin_dir = src_p / "bin"
        if bin_dir.is_dir():
            bins = [p for p in bin_dir.glob("*") if p.is_file() and not p.name.startswith(".")]
            if bins:
                return bins[0]

    # 3. pkg-config libdir resolution (for C/C++ libraries)
    if shutil.which("pkg-config") and comp.language in ("c/cpp", "c", "cpp", None):
        for cand in name_candidates:
            try:
                libdir = subprocess.check_output(
                    ["pkg-config", "--variable=libdir", cand],
                    text=True, stderr=subprocess.DEVNULL, timeout=2
                ).strip()
                if libdir and os.path.isdir(libdir):
                    for cand_name in name_candidates:
                        matches = glob.glob(f"{libdir}/{cand_name}.*") + glob.glob(f"{libdir}/lib{cand_name}.*")
                        valid_matches = [Path(m) for m in matches if Path(m).suffix.lower() in LIB_EXTENSIONS]
                        if valid_matches:
                            return valid_matches[0]
            except Exception:
                pass

    # 4. Host package managers (Homebrew Cellar search)
    cellar_bases = ["/opt/homebrew/Cellar", "/usr/local/Cellar"]
    for base in cellar_bases:
        if os.path.isdir(base):
            for cand in name_candidates:
                cellar_pkg = Path(base) / cand
                if cellar_pkg.is_dir():
                    libs = list(cellar_pkg.glob("*/lib/*.*"))
                    valid_libs = [p for p in libs if p.is_file() and p.suffix.lower() in LIB_EXTENSIONS]
                    if valid_libs:
                        return valid_libs[0]

    # 5. Standard library search paths (/usr/local/lib, /usr/lib)
    std_lib_dirs = ["/usr/local/lib", "/usr/lib"]
    for ldir in std_lib_dirs:
        if os.path.isdir(ldir):
            for cand in name_candidates:
                matches = glob.glob(f"{ldir}/{cand}.*") + glob.glob(f"{ldir}/lib{cand}.*")
                valid_matches = [Path(m) for m in matches if Path(m).suffix.lower() in LIB_EXTENSIONS]
                if valid_matches:
                    return valid_matches[0]

    return None
