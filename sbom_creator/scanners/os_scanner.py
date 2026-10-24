"""Scanner for operating system information and installed packages."""
import platform
import subprocess
import shutil
import os
import json
import plistlib
from pathlib import Path
from typing import List, Dict, Any, Set
from sbom_creator.models import Component
from sbom_creator.scanners.base import BaseScanner

class OSScanner(BaseScanner):
    """Scans the host operating system and optionally installed OS packages/apps."""

    def __init__(self, scan_packages: bool = True):
        self.scan_packages = scan_packages

    def scan(self) -> List[Component]:
        components: List[Component] = []
        os_family = platform.system()

        # 1. Base OS Component
        base_os = self._detect_base_os(os_family)
        if base_os:
            components.append(base_os)

        # 2. Installed OS Packages / Applications
        if self.scan_packages:
            if os_family == "Linux":
                components.extend(self._scan_linux_packages())
            elif os_family == "Windows":
                components.extend(self._scan_windows_packages())
            elif os_family == "Darwin":
                components.extend(self._scan_macos_packages())

        return components

    def _detect_base_os(self, os_family: str) -> Component:
        os_name = os_family
        os_version = platform.release()
        extra_props: Dict[str, Any] = {
            "architecture": platform.machine(),
            "platform": platform.platform()
        }

        if os_family == "Linux" and os.path.exists("/etc/os-release"):
            try:
                with open("/etc/os-release", "r", encoding="utf-8") as f:
                    data = {}
                    for line in f:
                        if "=" in line:
                            k, v = line.strip().split("=", 1)
                            data[k] = v.strip('"\'')
                    os_name = data.get("PRETTY_NAME", data.get("NAME", "Linux"))
                    os_version = data.get("VERSION_ID", platform.release())
            except Exception:
                pass
        elif os_family == "Windows":
            os_name = f"Microsoft Windows {platform.release()}"
            os_version = platform.version()
        elif os_family == "Darwin":
            os_name = "macOS"
            # Try sw_vers
            try:
                out = subprocess.check_output(["sw_vers"], text=True, stderr=subprocess.DEVNULL)
                for line in out.strip().splitlines():
                    if ":" in line:
                        k, v = line.split(":", 1)
                        k = k.strip()
                        v = v.strip()
                        if k == "ProductName":
                            os_name = v
                        elif k == "ProductVersion":
                            os_version = v
                        elif k == "BuildVersion":
                            extra_props["build_version"] = v
            except Exception:
                os_version = platform.mac_ver()[0] or platform.release()

            # Try sysctl for hardware model
            try:
                hw_model = subprocess.check_output(
                    ["sysctl", "-n", "hw.model"], text=True, stderr=subprocess.DEVNULL
                ).strip()
                if hw_model:
                    extra_props["hardware_model"] = hw_model
            except Exception:
                pass

        return Component(
            name=os_name,
            version=os_version,
            component_type="operating-system",
            description=f"{os_name} {os_version} ({platform.machine()})",
            purl=f"pkg:generic/{os_name.lower().replace(' ', '-')}@{os_version}",
            properties=extra_props
        )

    def _scan_linux_packages(self) -> List[Component]:
        components: List[Component] = []

        # Try dpkg-query (Debian/Ubuntu)
        if shutil.which("dpkg-query"):
            try:
                out = subprocess.check_output(
                    ["dpkg-query", "-W", "-f=${Package}\t${Version}\t${Architecture}\n"],
                    text=True, stderr=subprocess.DEVNULL
                )
                for line in out.strip().splitlines():
                    parts = line.split("\t")
                    if len(parts) >= 2:
                        pkg_name = parts[0]
                        pkg_ver = parts[1]
                        arch = parts[2] if len(parts) > 2 else ""
                        components.append(Component(
                            name=pkg_name,
                            version=pkg_ver,
                            component_type="library",
                            purl=f"pkg:deb/debian/{pkg_name}@{pkg_ver}?arch={arch}" if arch else f"pkg:deb/debian/{pkg_name}@{pkg_ver}",
                            properties={"package_manager": "dpkg", "architecture": arch}
                        ))
                return components
            except Exception:
                pass

        # Try rpm (RHEL/CentOS/Fedora)
        if shutil.which("rpm"):
            try:
                out = subprocess.check_output(
                    ["rpm", "-qa", "--queryformat", "%{NAME}\t%{VERSION}-%{RELEASE}\t%{ARCH}\n"],
                    text=True, stderr=subprocess.DEVNULL
                )
                for line in out.strip().splitlines():
                    parts = line.split("\t")
                    if len(parts) >= 2:
                        pkg_name = parts[0]
                        pkg_ver = parts[1]
                        arch = parts[2] if len(parts) > 2 else ""
                        components.append(Component(
                            name=pkg_name,
                            version=pkg_ver,
                            component_type="library",
                            purl=f"pkg:rpm/redhat/{pkg_name}@{pkg_ver}?arch={arch}" if arch else f"pkg:rpm/redhat/{pkg_name}@{pkg_ver}",
                            properties={"package_manager": "rpm", "architecture": arch}
                        ))
                return components
            except Exception:
                pass

        return components

    def _scan_windows_packages(self) -> List[Component]:
        components: List[Component] = []
        if shutil.which("winget"):
            try:
                out = subprocess.check_output(
                    ["winget", "list"],
                    text=True, stderr=subprocess.DEVNULL, timeout=10
                )
                lines = out.strip().splitlines()
                start_parsing = False
                for line in lines:
                    if "---" in line:
                        start_parsing = True
                        continue
                    if start_parsing and line.strip():
                        parts = line.split()
                        if len(parts) >= 3:
                            components.append(Component(
                                name=parts[0],
                                version=parts[2],
                                component_type="application",
                                purl=f"pkg:winget/{parts[0]}@{parts[2]}",
                                properties={"package_manager": "winget"}
                            ))
            except Exception:
                pass
        return components

    def _scan_macos_packages(self) -> List[Component]:
        """Scan Homebrew packages and installed macOS applications."""
        components: List[Component] = []
        seen_names: Set[str] = set()

        # 1. Homebrew Formulae (Cellar)
        homebrew_cellars = ["/opt/homebrew/Cellar", "/usr/local/Cellar"]
        for cellar in homebrew_cellars:
            if os.path.isdir(cellar):
                try:
                    for pkg_name in os.listdir(cellar):
                        pkg_path = os.path.join(cellar, pkg_name)
                        if os.path.isdir(pkg_path) and not pkg_name.startswith("."):
                            # Get versions
                            versions = [v for v in os.listdir(pkg_path) if not v.startswith(".")]
                            for ver in versions:
                                ver_path = os.path.join(pkg_path, ver)
                                receipt_file = os.path.join(ver_path, "INSTALL_RECEIPT.json")
                                license_info = None
                                desc = None
                                if os.path.isfile(receipt_file):
                                    try:
                                        with open(receipt_file, "r", encoding="utf-8") as rf:
                                            receipt = json.load(rf)
                                            license_info = receipt.get("license")
                                            desc = receipt.get("desc")
                                    except Exception:
                                        pass

                                components.append(Component(
                                    name=pkg_name,
                                    version=ver,
                                    component_type="library",
                                    license=str(license_info) if license_info else None,
                                    description=desc,
                                    purl=f"pkg:brew/{pkg_name}@{ver}",
                                    properties={
                                        "package_manager": "homebrew-formula",
                                        "source_dir": ver_path
                                    }
                                ))
                                seen_names.add(pkg_name.lower())
                except Exception:
                    pass

        # 2. Homebrew Casks (Caskroom)
        homebrew_caskrooms = ["/opt/homebrew/Caskroom", "/usr/local/Caskroom"]
        for caskroom in homebrew_caskrooms:
            if os.path.isdir(caskroom):
                try:
                    for cask_name in os.listdir(caskroom):
                        cask_path = os.path.join(caskroom, cask_name)
                        if os.path.isdir(cask_path) and not cask_name.startswith("."):
                            versions = [v for v in os.listdir(cask_path) if not v.startswith(".")]
                            for ver in versions:
                                components.append(Component(
                                    name=cask_name,
                                    version=ver,
                                    component_type="application",
                                    purl=f"pkg:brew/cask/{cask_name}@{ver}",
                                    properties={
                                        "package_manager": "homebrew-cask",
                                        "source_dir": os.path.join(cask_path, ver)
                                    }
                                ))
                                seen_names.add(cask_name.lower())
                except Exception:
                    pass

        # 3. macOS Installed Applications (/Applications, ~/Applications)
        app_dirs = [
            "/Applications",
            os.path.expanduser("~/Applications")
        ]
        for app_dir in app_dirs:
            if os.path.isdir(app_dir):
                try:
                    for item in os.listdir(app_dir):
                        if item.endswith(".app"):
                            plist_path = os.path.join(app_dir, item, "Contents", "Info.plist")
                            if os.path.isfile(plist_path):
                                try:
                                    with open(plist_path, "rb") as fp:
                                        pl = plistlib.load(fp)
                                        name = pl.get("CFBundleDisplayName") or pl.get("CFBundleName") or item[:-4]
                                        ver = pl.get("CFBundleShortVersionString") or pl.get("CFBundleVersion") or "unknown"
                                        bundle_id = pl.get("CFBundleIdentifier")

                                        # Avoid duplicating apps already found in brew casks
                                        clean_id = (bundle_id or name).lower()
                                        if clean_id not in seen_names:
                                            seen_names.add(clean_id)
                                            components.append(Component(
                                                name=name,
                                                version=str(ver),
                                                component_type="application",
                                                purl=f"pkg:generic/apple-app/{name.replace(' ', '-')}@{ver}",
                                                properties={
                                                    "bundle_id": bundle_id or "",
                                                    "app_path": os.path.join(app_dir, item)
                                                }
                                            ))
                                except Exception:
                                    pass
                except Exception:
                    pass

        return components
