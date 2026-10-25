"""Scanner for software projects across multiple programming languages.

Supported languages & manifests:
- Python: requirements.txt, pyproject.toml
- TypeScript / JavaScript: package.json
- Go: go.mod
- Java: pom.xml, build.gradle
- C / C++:
    - Package/Build managers: CMakeLists.txt, conanfile.txt, vcpkg.json, meson.build, configure.ac
    - Makefiles: Makefile, makefile, GNUmakefile (parsing -l<lib> and pkg-config)
    - Source/Headers: Static analysis of #include <...> for external OSS libraries
- C#: *.csproj
"""
import os
import re
import json
from pathlib import Path
from typing import List, Set, Dict, Optional, Tuple
import xml.etree.ElementTree as ET

from sbom_creator.models import Component, Checksum
from sbom_creator.scanners.base import BaseScanner
from sbom_creator.checksum import compute_file_checksums, compute_content_checksums

# Standard C / C++ and POSIX headers to ignore during source inspection
STD_C_CPP_HEADERS: Set[str] = {
    # C Standard
    "assert.h", "complex.h", "ctype.h", "errno.h", "fenv.h", "float.h", "inttypes.h",
    "iso646.h", "limits.h", "locale.h", "math.h", "setjmp.h", "signal.h", "stdalign.h",
    "stdarg.h", "stdatomic.h", "stdbool.h", "stddef.h", "stdint.h", "stdio.h", "stdlib.h",
    "stdnoreturn.h", "string.h", "tgmath.h", "threads.h", "time.h", "uchar.h", "wchar.h", "wctype.h",
    # POSIX / System
    "unistd.h", "fcntl.h", "pthread.h", "dirent.h", "sys/types.h", "sys/stat.h",
    "sys/socket.h", "sys/time.h", "sys/wait.h", "sys/mman.h", "sys/ioctl.h", "sys/select.h",
    "sys/param.h", "sys/resource.h", "sys/uio.h", "sys/un.h",
    "netinet/in.h", "netinet/tcp.h", "netdb.h", "arpa/inet.h", "poll.h", "termios.h",
    "pwd.h", "grp.h", "utime.h",
    # C++ Standard
    "iostream", "vector", "string", "map", "set", "unordered_map", "unordered_set",
    "memory", "algorithm", "functional", "utility", "thread", "mutex", "chrono",
    "optional", "variant", "any", "span", "string_view", "filesystem", "format",
    "ranges", "coroutine", "concepts", "bit", "compare", "numbers", "tuple",
    "queue", "stack", "deque", "list", "forward_list", "array", "iterator",
    "exception", "stdexcept", "cassert", "cctype", "cerrno", "cmath", "cstdint",
    "cstdio", "cstdlib", "cstring", "ctime", "fstream", "sstream", "iomanip",
    "streambuf", "numeric", "random", "regex", "valarray", "typeinfo", "type_traits",
    "new", "condition_variable", "shared_mutex", "future", "barrier", "latch", "semaphore"
}

# Known library signatures mapped from header prefixes or filenames
KNOWN_HEADER_LIBRARIES: Dict[str, Tuple[str, str]] = {
    "openssl/": ("OpenSSL", "pkg:generic/openssl"),
    "curl/": ("libcurl", "pkg:generic/curl"),
    "boost/": ("Boost", "pkg:generic/boost"),
    "zlib.h": ("zlib", "pkg:generic/zlib"),
    "sqlite3.h": ("SQLite", "pkg:generic/sqlite3"),
    "nlohmann/": ("nlohmann-json", "pkg:generic/nlohmann-json"),
    "spdlog/": ("spdlog", "pkg:generic/spdlog"),
    "fmt/": ("fmt", "pkg:generic/fmt"),
    "opencv2/": ("OpenCV", "pkg:generic/opencv"),
    "Eigen/": ("Eigen", "pkg:generic/eigen"),
    "eigen3/": ("Eigen", "pkg:generic/eigen"),
    "google/protobuf/": ("protobuf", "pkg:generic/protobuf"),
    "protobuf/": ("protobuf", "pkg:generic/protobuf"),
    "grpc/": ("gRPC", "pkg:generic/grpc"),
    "grpcpp/": ("gRPC", "pkg:generic/grpc"),
    "gtest/": ("googletest", "pkg:generic/googletest"),
    "yaml-cpp/": ("yaml-cpp", "pkg:generic/yaml-cpp"),
    "png.h": ("libpng", "pkg:generic/libpng"),
    "jpeglib.h": ("libjpeg", "pkg:generic/libjpeg"),
    "uv.h": ("libuv", "pkg:generic/libuv"),
    "zmq.h": ("ZeroMQ", "pkg:generic/zeromq"),
    "zmq.hpp": ("ZeroMQ", "pkg:generic/zeromq"),
    "json-c/": ("json-c", "pkg:generic/json-c"),
    "glib.h": ("glib", "pkg:generic/glib"),
    "glib/": ("glib", "pkg:generic/glib"),
    "libxml/": ("libxml2", "pkg:generic/libxml2"),
    "archive.h": ("libarchive", "pkg:generic/libarchive")
}

# Standard OS/compiler link libraries to ignore in Makefiles
STD_MAKE_LIBS = {"m", "c", "pthread", "dl", "rt", "stdc++", "gcc", "gcc_s", "atomic"}

C_CPP_EXTENSIONS = {".c", ".cpp", ".cc", ".cxx", ".h", ".hpp", ".hxx"}

class ProjectScanner(BaseScanner):
    """Scans a directory tree for language manifests, Makefiles, and source files."""

    def __init__(self, root_dir: str):
        self.root_dir = Path(root_dir).resolve()
        # Collect local header filenames in project to avoid treating internal headers as third-party
        self.local_headers: Set[str] = set()

    def scan(self) -> List[Component]:
        components: List[Component] = []
        seen_purls: Set[str] = set()

        # Step 1: Pre-index local header files
        for dirpath, dirnames, filenames in os.walk(self.root_dir):
            dirnames[:] = [d for d in dirnames if d not in {
                ".git", "node_modules", ".venv", "venv", "__pycache__", "target", "bin", "obj", ".idea", ".vscode"
            }]
            for file in filenames:
                if Path(file).suffix.lower() in {".h", ".hpp", ".hxx"}:
                    self.local_headers.add(file)
                    # Also relative paths like "utils/helper.h"
                    rel_p = str(Path(dirpath, file).relative_to(self.root_dir))
                    self.local_headers.add(rel_p)

        # Step 2: Walk directory and scan files
        for dirpath, dirnames, filenames in os.walk(self.root_dir):
            dirnames[:] = [d for d in dirnames if d not in {
                ".git", "node_modules", ".venv", "venv", "__pycache__", "target", "bin", "obj", ".idea", ".vscode"
            }]

            current_dir = Path(dirpath)

            for file in filenames:
                file_path = current_dir / file
                file_comps: List[Component] = []

                # Python
                if file == "requirements.txt":
                    file_comps.extend(self._parse_requirements_txt(file_path))
                elif file == "pyproject.toml":
                    file_comps.extend(self._parse_pyproject_toml(file_path))

                # TypeScript / JavaScript
                elif file == "package.json":
                    file_comps.extend(self._parse_package_json(file_path))

                # Go
                elif file == "go.mod":
                    file_comps.extend(self._parse_go_mod(file_path))

                # Java
                elif file == "pom.xml":
                    file_comps.extend(self._parse_pom_xml(file_path))
                elif file in ("build.gradle", "build.gradle.kts"):
                    file_comps.extend(self._parse_gradle(file_path))

                # C / C++ Package & Build Managers
                elif file == "vcpkg.json":
                    file_comps.extend(self._parse_vcpkg_json(file_path))
                elif file == "conanfile.txt":
                    file_comps.extend(self._parse_conanfile_txt(file_path))
                elif file == "CMakeLists.txt":
                    file_comps.extend(self._parse_cmakelists(file_path))
                elif file in ("Makefile", "makefile", "GNUmakefile"):
                    file_comps.extend(self._parse_makefile(file_path))
                elif file == "meson.build":
                    file_comps.extend(self._parse_meson(file_path))
                elif file in ("configure.ac", "configure.in"):
                    file_comps.extend(self._parse_autotools(file_path))

                # C / C++ Source / Header files (#include <...>)
                elif Path(file).suffix.lower() in C_CPP_EXTENSIONS:
                    file_comps.extend(self._parse_cpp_source(file_path))

                # C#
                elif file.endswith(".csproj"):
                    file_comps.extend(self._parse_csproj(file_path))

                if file_comps:
                    file_cs = compute_file_checksums(file_path)
                    sha256_val = next((cs.value for cs in file_cs if cs.algorithm == "SHA256"), None)
                    if sha256_val:
                        for comp in file_comps:
                            prop_key = "source_checksum_sha256" if "source_file" in comp.properties else "manifest_checksum_sha256"
                            comp.properties[prop_key] = sha256_val

                for comp in file_comps:
                    # De-duplicate by purl or (language, name, version)
                    key = comp.purl or f"{comp.language}:{comp.name}:{comp.version}"
                    if key not in seen_purls:
                        seen_purls.add(key)
                        components.append(comp)

        return components

    # --- Python ---
    def _parse_requirements_txt(self, file_path: Path) -> List[Component]:
        comps = []
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#") or line.startswith("-"):
                        continue
                    m = re.match(r"^([a-zA-Z0-9_\-\.]+)\s*([=><~!^]{1,2}\s*[a-zA-Z0-9_\-\.]+)?", line)
                    if m:
                        name = m.group(1)
                        raw_ver = m.group(2) or ""
                        version = re.sub(r"^[=><~!^]+", "", raw_ver).strip() if raw_ver else "unknown"
                        comps.append(Component(
                            name=name,
                            version=version,
                            language="python",
                            component_type="library",
                            purl=f"pkg:pypi/{name}@{version}" if version != "unknown" else f"pkg:pypi/{name}",
                            properties={"manifest": str(file_path.relative_to(self.root_dir))}
                        ))
        except Exception:
            pass
        return comps

    def _parse_pyproject_toml(self, file_path: Path) -> List[Component]:
        comps = []
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                content = f.read()
            deps_match = re.search(r"dependencies\s*=\s*\[(.*?)\]", content, re.DOTALL)
            if deps_match:
                dep_lines = deps_match.group(1).splitlines()
                for d in dep_lines:
                    d = d.strip().strip('",\'')
                    if d:
                        m = re.match(r"^([a-zA-Z0-9_\-\.]+)\s*([=><~!^]{1,2}\s*[a-zA-Z0-9_\-\.]+)?", d)
                        if m:
                            name = m.group(1)
                            raw_ver = m.group(2) or ""
                            version = re.sub(r"^[=><~!^]+", "", raw_ver).strip() if raw_ver else "unknown"
                            comps.append(Component(
                                name=name,
                                version=version,
                                language="python",
                                component_type="library",
                                purl=f"pkg:pypi/{name}@{version}" if version != "unknown" else f"pkg:pypi/{name}",
                                properties={"manifest": str(file_path.relative_to(self.root_dir))}
                            ))
        except Exception:
            pass
        return comps

    # --- TypeScript / JavaScript ---
    def _parse_package_json(self, file_path: Path) -> List[Component]:
        comps = []
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            
            for section in ["dependencies", "devDependencies"]:
                for name, ver in data.get(section, {}).items():
                    clean_ver = re.sub(r"^[\^~v>=<]+", "", ver).strip()
                    comps.append(Component(
                        name=name,
                        version=clean_ver if clean_ver else "unknown",
                        language="typescript",
                        component_type="library",
                        purl=f"pkg:npm/{name}@{clean_ver}" if clean_ver else f"pkg:npm/{name}",
                        properties={
                            "scope": "dev" if section == "devDependencies" else "prod",
                            "manifest": str(file_path.relative_to(self.root_dir))
                        }
                    ))
        except Exception:
            pass
        return comps

    # --- Go ---
    def _parse_go_mod(self, file_path: Path) -> List[Component]:
        comps = []
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                in_require_block = False
                for line in f:
                    line = line.strip()
                    if line.startswith("require ("):
                        in_require_block = True
                        continue
                    if in_require_block and line == ")":
                        in_require_block = False
                        continue

                    if in_require_block or line.startswith("require "):
                        line_content = line.removeprefix("require ").strip()
                        parts = line_content.split()
                        if len(parts) >= 2:
                            mod_name, mod_ver = parts[0], parts[1]
                            comps.append(Component(
                                name=mod_name,
                                version=mod_ver,
                                language="go",
                                component_type="library",
                                purl=f"pkg:golang/{mod_name}@{mod_ver}",
                                properties={"manifest": str(file_path.relative_to(self.root_dir))}
                            ))
        except Exception:
            pass
        return comps

    # --- Java ---
    def _parse_pom_xml(self, file_path: Path) -> List[Component]:
        comps = []
        try:
            tree = ET.parse(file_path)
            root = tree.getroot()
            ns = {"m": root.tag.split("}")[0].strip("{")} if "}" in root.tag else {}
            
            xpath = ".//m:dependency" if ns else ".//dependency"
            for dep in root.findall(xpath, ns):
                group_elem = dep.find("m:groupId", ns) if ns else dep.find("groupId")
                artifact_elem = dep.find("m:artifactId", ns) if ns else dep.find("artifactId")
                ver_elem = dep.find("m:version", ns) if ns else dep.find("version")

                group_id = group_elem.text.strip() if group_elem is not None and group_elem.text else "unknown"
                artifact_id = artifact_elem.text.strip() if artifact_elem is not None and artifact_elem.text else "unknown"
                version = ver_elem.text.strip() if ver_elem is not None and ver_elem.text else "unknown"

                name = f"{group_id}:{artifact_id}" if group_id != "unknown" else artifact_id
                comps.append(Component(
                    name=name,
                    version=version,
                    language="java",
                    component_type="library",
                    purl=f"pkg:maven/{group_id}/{artifact_id}@{version}",
                    properties={"manifest": str(file_path.relative_to(self.root_dir))}
                ))
        except Exception:
            pass
        return comps

    def _parse_gradle(self, file_path: Path) -> List[Component]:
        comps = []
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    m = re.search(r"(?:implementation|api|compileOnly|runtimeOnly)\s*[\(\"']\s*([a-zA-Z0-9_\-\.]+):([a-zA-Z0-9_\-\.]+):([a-zA-Z0-9_\-\.]+)\s*[\)\"']", line)
                    if m:
                        group_id, artifact_id, version = m.group(1), m.group(2), m.group(3)
                        comps.append(Component(
                            name=f"{group_id}:{artifact_id}",
                            version=version,
                            language="java",
                            component_type="library",
                            purl=f"pkg:maven/{group_id}/{artifact_id}@{version}",
                            properties={"manifest": str(file_path.relative_to(self.root_dir))}
                        ))
        except Exception:
            pass
        return comps

    # --- C / C++ Package & Build Managers ---
    def _parse_vcpkg_json(self, file_path: Path) -> List[Component]:
        comps = []
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            for dep in data.get("dependencies", []):
                if isinstance(dep, str):
                    comps.append(Component(
                        name=dep,
                        version="unknown",
                        language="cpp",
                        component_type="library",
                        purl=f"pkg:vcpkg/{dep}",
                        properties={"manifest": str(file_path.relative_to(self.root_dir))}
                    ))
                elif isinstance(dep, dict) and "name" in dep:
                    ver = dep.get("version>=", "unknown")
                    comps.append(Component(
                        name=dep["name"],
                        version=ver,
                        language="cpp",
                        component_type="library",
                        purl=f"pkg:vcpkg/{dep['name']}@{ver}" if ver != "unknown" else f"pkg:vcpkg/{dep['name']}",
                        properties={"manifest": str(file_path.relative_to(self.root_dir))}
                    ))
        except Exception:
            pass
        return comps

    def _parse_conanfile_txt(self, file_path: Path) -> List[Component]:
        comps = []
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                in_requires = False
                for line in f:
                    line = line.strip()
                    if line.startswith("[requires]"):
                        in_requires = True
                        continue
                    if in_requires and line.startswith("["):
                        in_requires = False
                        continue
                    if in_requires and line and not line.startswith("#"):
                        parts = line.split("/")
                        name = parts[0]
                        ver = parts[1].split("@")[0] if len(parts) > 1 else "unknown"
                        comps.append(Component(
                            name=name,
                            version=ver,
                            language="cpp",
                            component_type="library",
                            purl=f"pkg:conan/{name}@{ver}",
                            properties={"manifest": str(file_path.relative_to(self.root_dir))}
                        ))
        except Exception:
            pass
        return comps

    def _parse_cmakelists(self, file_path: Path) -> List[Component]:
        comps = []
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                for line in f:
                    m = re.search(r"find_package\s*\(\s*([a-zA-Z0-9_\-]+)(?:\s+([0-9\.]+))?", line, re.IGNORECASE)
                    if m:
                        pkg_name = m.group(1)
                        pkg_ver = m.group(2) or "unknown"
                        comps.append(Component(
                            name=pkg_name,
                            version=pkg_ver,
                            language="c/cpp",
                            component_type="library",
                            purl=f"pkg:cmake/{pkg_name}@{pkg_ver}" if pkg_ver != "unknown" else f"pkg:cmake/{pkg_name}",
                            properties={"manifest": str(file_path.relative_to(self.root_dir))}
                        ))
        except Exception:
            pass
        return comps

    # --- C / C++ Fallbacks (Makefile, Meson, Autotools, Source Headers) ---
    def _parse_makefile(self, file_path: Path) -> List[Component]:
        """Parse Makefiles for -l<lib> flags and pkg-config dependencies."""
        comps = []
        seen_libs = set()
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()

            # 1. Match -l<lib> (e.g., -lssl, -lcurl, -lz)
            for m in re.finditer(r"(?:^|\s)-l([a-zA-Z0-9_\-\.]+)", content):
                lib = m.group(1)
                if lib not in STD_MAKE_LIBS and lib not in seen_libs:
                    seen_libs.add(lib)
                    comps.append(Component(
                        name=f"lib{lib}" if not lib.startswith("lib") else lib,
                        version="unknown",
                        language="c/cpp",
                        component_type="library",
                        purl=f"pkg:generic/{lib}",
                        properties={
                            "manifest": str(file_path.relative_to(self.root_dir)),
                            "detection_method": "makefile_linker_flag",
                            "linker_flag": f"-l{lib}"
                        }
                    ))

            # 2. Match pkg-config --libs <package> or pkg-config <package>
            for m in re.finditer(r"pkg-config\s+(?:--[a-z\-]+\s+)*([a-zA-Z0-9_\-\.]+)", content):
                pkg = m.group(1)
                if not pkg.startswith("-") and pkg not in seen_libs:
                    seen_libs.add(pkg)
                    comps.append(Component(
                        name=pkg,
                        version="unknown",
                        language="c/cpp",
                        component_type="library",
                        purl=f"pkg:pkgconfig/{pkg}",
                        properties={
                            "manifest": str(file_path.relative_to(self.root_dir)),
                            "detection_method": "makefile_pkg_config"
                        }
                    ))
        except Exception:
            pass
        return comps

    def _parse_meson(self, file_path: Path) -> List[Component]:
        """Parse meson.build for dependency('...') declarations."""
        comps = []
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
            for m in re.finditer(r"dependency\s*\(\s*['\"]([a-zA-Z0-9_\-\.]+)['\"]", content):
                name = m.group(1)
                comps.append(Component(
                    name=name,
                    version="unknown",
                    language="c/cpp",
                    component_type="library",
                    purl=f"pkg:generic/{name}",
                    properties={"manifest": str(file_path.relative_to(self.root_dir)), "detection_method": "meson"}
                ))
        except Exception:
            pass
        return comps

    def _parse_autotools(self, file_path: Path) -> List[Component]:
        """Parse configure.ac / configure.in for PKG_CHECK_MODULES or AC_CHECK_LIB."""
        comps = []
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
            # AC_CHECK_LIB([z], [inflate])
            for m in re.finditer(r"AC_CHECK_LIB\s*\(\s*\[?([a-zA-Z0-9_\-]+)\]?", content):
                lib = m.group(1)
                if lib not in STD_MAKE_LIBS:
                    comps.append(Component(
                        name=f"lib{lib}" if not lib.startswith("lib") else lib,
                        version="unknown",
                        language="c/cpp",
                        component_type="library",
                        purl=f"pkg:generic/{lib}",
                        properties={"manifest": str(file_path.relative_to(self.root_dir)), "detection_method": "autotools"}
                    ))
            # PKG_CHECK_MODULES(NAME, [libfoo >= 1.0])
            for m in re.finditer(r"PKG_CHECK_MODULES\s*\([^,]+,\s*\[?([a-zA-Z0-9_\-\.]+)", content):
                pkg = m.group(1)
                comps.append(Component(
                    name=pkg,
                    version="unknown",
                    language="c/cpp",
                    component_type="library",
                    purl=f"pkg:pkgconfig/{pkg}",
                    properties={"manifest": str(file_path.relative_to(self.root_dir)), "detection_method": "autotools"}
                ))
        except Exception:
            pass
        return comps

    def _parse_cpp_source(self, file_path: Path) -> List[Component]:
        """Inspect #include <...> in C/C++ source/header files to identify third-party OSS libraries."""
        comps = []
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    line = line.strip()
                    if not line.startswith("#"):
                        continue
                    # Match #include <something> or #include "something"
                    m = re.match(r"#\s*include\s*[<\"]([^>\"]+)[>\"]", line)
                    if not m:
                        continue
                    header = m.group(1).strip()

                    # 1. Skip standard C / C++ / POSIX headers
                    if header in STD_C_CPP_HEADERS or header.lower() in STD_C_CPP_HEADERS:
                        continue

                    # 2. Skip local internal project headers
                    if header in self.local_headers or Path(header).name in self.local_headers:
                        continue

                    # 3. Match against known third-party library signatures
                    matched = False
                    for pattern, (lib_name, purl_base) in KNOWN_HEADER_LIBRARIES.items():
                        if pattern.endswith("/") and header.startswith(pattern):
                            comps.append(Component(
                                name=lib_name,
                                version="unknown",
                                language="c/cpp",
                                component_type="library",
                                purl=f"{purl_base}",
                                properties={
                                    "source_file": str(file_path.relative_to(self.root_dir)),
                                    "detected_header": header,
                                    "detection_method": "source_header_inspection"
                                }
                            ))
                            matched = True
                            break
                        elif not pattern.endswith("/") and header == pattern:
                            comps.append(Component(
                                name=lib_name,
                                version="unknown",
                                language="c/cpp",
                                component_type="library",
                                purl=f"{purl_base}",
                                properties={
                                    "source_file": str(file_path.relative_to(self.root_dir)),
                                    "detected_header": header,
                                    "detection_method": "source_header_inspection"
                                }
                            ))
                            matched = True
                            break

                    # 4. Fallback: if header is inside a subfolder <foo/bar.h> and foo is not a system path like sys/
                    if not matched and "/" in header and not header.startswith(("sys/", "net/", "netinet/", "arpa/")):
                        prefix = header.split("/")[0]
                        if prefix not in {"linux", "darwin", "windows", "internal"}:
                            comps.append(Component(
                                name=prefix,
                                version="unknown",
                                language="c/cpp",
                                component_type="library",
                                purl=f"pkg:generic/{prefix}",
                                properties={
                                    "source_file": str(file_path.relative_to(self.root_dir)),
                                    "detected_header": header,
                                    "detection_method": "source_header_inspection"
                                }
                            ))
        except Exception:
            pass
        return comps

    # --- C# ---
    def _parse_csproj(self, file_path: Path) -> List[Component]:
        comps = []
        try:
            tree = ET.parse(file_path)
            root = tree.getroot()
            for pkg in root.findall(".//PackageReference"):
                name = pkg.get("Include") or pkg.get("Update")
                version = pkg.get("Version")
                if not version:
                    ver_elem = pkg.find("Version")
                    if ver_elem is not None and ver_elem.text:
                        version = ver_elem.text.strip()
                if name:
                    version = version or "unknown"
                    comps.append(Component(
                        name=name,
                        version=version,
                        language="csharp",
                        component_type="library",
                        purl=f"pkg:nuget/{name}@{version}" if version != "unknown" else f"pkg:nuget/{name}",
                        properties={"manifest": str(file_path.relative_to(self.root_dir))}
                    ))
        except Exception:
            pass
        return comps
