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
        # Check Java (Production only)
        self.assertIn("com.google.guava:guava", names)
        self.assertIn("org.springframework.boot:spring-boot-starter-web", names)
        self.assertIn("org.apache.commons:commons-lang3", names)
        self.assertIn("org.postgresql:postgresql", names)
        self.assertIn("io.netty:netty-all", names)

        # Ensure Java test & build libraries are EXCLUDED
        self.assertNotIn("org.junit.jupiter:junit-jupiter", names)
        self.assertNotIn("org.projectlombok:lombok", names)
        self.assertNotIn("org.junit.platform:junit-platform-launcher", names)

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
        output1 = generate_sbom(target_path=str(self.sample_dir), format_name="spdx")
        output2 = generate_sbom(target_path=str(self.sample_dir), format_name="spdx")
        self.assertIn('"spdxVersion": "SPDX-2.3"', output1)
        self.assertIn('"documentNamespace": "https://spdx.org/spdxdocs/sample_project"', output1)
        self.assertIn('"relationships": [', output1)
        self.assertIn('"relationshipType": "DESCRIBES"', output1)
        self.assertIn('"relationshipType": "DEPENDS_ON"', output1)
        self.assertIn('"checksums": [', output1)
        self.assertIn('"algorithm": "SHA256"', output1)
        self.assertIn('"referenceType": "cpe23Type"', output1)
        self.assertIn('"sourceInfo":', output1)

        # Verify determinism across multiple runs (no random UUID in namespace)
        import json
        doc1 = json.loads(output1)
        doc2 = json.loads(output2)
        self.assertEqual(doc1["documentNamespace"], doc2["documentNamespace"])
        self.assertEqual(doc1["documentNamespace"], "https://spdx.org/spdxdocs/sample_project")

    def test_generate_csv(self):
        output = generate_sbom(target_path=str(self.sample_dir), format_name="csv")
        self.assertTrue(output.startswith("Name,Version,Type,Language,PURL,CPE,License,Manifest/Source"))

if __name__ == "__main__":
    unittest.main()
