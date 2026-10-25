"""Unit tests for version and license inference resolvers."""
import unittest
from sbom_creator.models import Component
from sbom_creator.resolver import enrich_components, KNOWN_LICENSES

class TestResolver(unittest.TestCase):
    def test_known_licenses(self):
        comp = Component(name="libcurl", version="8.0.0")
        enrich_components([comp])
        self.assertEqual(comp.license, "curl")
        self.assertEqual(comp.properties.get("license_source"), "known_oss_preset")

    def test_sqlite_license(self):
        comp = Component(name="sqlite3", version="3.40.0")
        enrich_components([comp])
        self.assertEqual(comp.license, "blessing")

    def test_component_overrides(self):
        comp = Component(name="my-custom-lib", version="unknown", license=None)
        overrides = {
            "my-custom-lib": {
                "version": "1.2.3",
                "license": "MIT"
            }
        }
        enrich_components([comp], overrides=overrides)
        self.assertEqual(comp.version, "1.2.3")
        self.assertEqual(comp.license, "MIT")
        self.assertEqual(comp.properties.get("version_source"), "config_override")

    def test_purl_cpe_synchronization(self):
        comp = Component(name="curl", version="unknown", purl="pkg:generic/curl")
        overrides = {
            "curl": {
                "version": "8.7.1"
            }
        }
        enrich_components([comp], overrides=overrides)
        self.assertEqual(comp.version, "8.7.1")
        self.assertEqual(comp.purl, "pkg:generic/curl@8.7.1")
    def test_artifact_checksum_override(self):
        comp = Component(name="my-lib", version="1.0.0")
        overrides = {
            "my-lib": {
                "sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "sha1": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                "package_file_name": "libmylib.so"
            }
        }
        enrich_components([comp], overrides=overrides)
        self.assertEqual(len(comp.checksums), 2)
        self.assertEqual(comp.checksums[0].algorithm, "SHA256")
        self.assertEqual(comp.checksums[0].value, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
        self.assertEqual(comp.properties.get("checksum_source"), "config_override")
        self.assertEqual(comp.properties.get("artifact_file"), "libmylib.so")

if __name__ == "__main__":
    unittest.main()
