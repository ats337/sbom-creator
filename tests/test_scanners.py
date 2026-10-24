"""Unit tests for SBOM Creator scanners and formatters."""
import unittest
from pathlib import Path

from sbom_creator.scanners.project_scanner import ProjectScanner
from sbom_creator.scanners.os_scanner import OSScanner
from sbom_creator.core import generate_sbom

class TestSBOMCreator(unittest.TestCase):
    def setUp(self):
        self.sample_dir = Path(__file__).parent.parent / "examples" / "sample_project"

    def test_project_scanner(self):
        scanner = ProjectScanner(root_dir=str(self.sample_dir))
        comps = scanner.scan()
        names = {c.name for c in comps}
        languages = {c.language for c in comps if c.language}

        # Check Python
        self.assertIn("requests", names)
        # Check TypeScript
        self.assertIn("react", names)
        # Check Go
        self.assertIn("github.com/gin-gonic/gin", names)
        # Check Java
        self.assertIn("com.google.guava:guava", names)
        # Check C/C++
        self.assertIn("OpenSSL", names)
        self.assertIn("fmt", names)
        # Check C#
        self.assertIn("Newtonsoft.Json", names)

        self.assertIn("python", languages)
        self.assertIn("typescript", languages)
        self.assertIn("go", languages)
        self.assertIn("java", languages)
        self.assertIn("csharp", languages)

    def test_legacy_c_scanner(self):
        legacy_dir = self.sample_dir / "legacy_c_app"
        scanner = ProjectScanner(root_dir=str(legacy_dir))
        comps = scanner.scan()
        names = {c.name for c in comps}

        # Makefile flags
        self.assertIn("libcurl", names)
        self.assertIn("libsqlite3", names)
        # Source headers
        self.assertIn("OpenSSL", names)
        self.assertIn("libuv", names)


    def test_os_scanner(self):
        scanner = OSScanner(scan_packages=False)
        comps = scanner.scan()
        self.assertGreaterEqual(len(comps), 1)
        self.assertEqual(comps[0].component_type, "operating-system")

    def test_generate_cyclonedx(self):
        output = generate_sbom(target_path=str(self.sample_dir), format_name="cyclonedx")
        self.assertIn('"bomFormat": "CycloneDX"', output)
        self.assertIn('"specVersion": "1.5"', output)

    def test_generate_spdx(self):
        output = generate_sbom(target_path=str(self.sample_dir), format_name="spdx")
        self.assertIn('"spdxVersion": "SPDX-2.3"', output)
        self.assertIn('"relationships": [', output)
        self.assertIn('"relationshipType": "DESCRIBES"', output)
        self.assertIn('"relationshipType": "DEPENDS_ON"', output)
        self.assertIn('"checksums": [', output)
        self.assertIn('"algorithm": "SHA256"', output)
        self.assertIn('"referenceType": "cpe23Type"', output)

    def test_generate_csv(self):
        output = generate_sbom(target_path=str(self.sample_dir), format_name="csv")
        self.assertTrue(output.startswith("Name,Version,Type,Language,PURL,License,Manifest/Source"))

if __name__ == "__main__":
    unittest.main()
