"""Unit tests for configuration loading and priority resolution."""
import unittest
import json
import tempfile
from pathlib import Path

from sbom_creator.config import resolve_settings, load_config_file, DEFAULT_CONFIG

class TestConfigResolution(unittest.TestCase):
    def test_default_values(self):
        settings = resolve_settings(cli_args={}, config_file_path=None)
        self.assertEqual(settings["format"], "cyclonedx")
        self.assertEqual(settings["version"], "latest")
        self.assertEqual(settings["copyright"], "NOASSERTION")
        self.assertEqual(settings["tool_name"], "sbom-creator")
        self.assertNotIn("data_license", settings)

    def test_cli_overrides_defaults(self):
        cli = {
            "format": "spdx-json",
            "version": "1.5.0",
            "license": "MIT"
        }
        settings = resolve_settings(cli_args=cli, config_file_path=None)
        self.assertEqual(settings["format"], "spdx-json")
        self.assertEqual(settings["version"], "1.5.0")
        self.assertEqual(settings["license"], "MIT")
        # Defaults for unspecified
        self.assertEqual(settings["copyright"], "NOASSERTION")

    def test_config_file_overrides_cli_and_defaults(self):
        # Create temp config file
        cfg_data = {
            "name": "from-config",
            "version": "2.0.0",
            "license": "Apache-2.0"
        }
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
            json.dump(cfg_data, f)
            cfg_path = f.name

        try:
            cli = {
                "name": "from-cli",        # Should be ignored (config priority)
                "version": "9.9.9",       # Should be ignored (config priority)
                "creator": "Person: Bob"  # Not in config, so CLI value used
            }
            settings = resolve_settings(cli_args=cli, config_file_path=cfg_path)
            
            # Config file takes priority over CLI
            self.assertEqual(settings["name"], "from-config")
            self.assertEqual(settings["version"], "2.0.0")
            self.assertEqual(settings["license"], "Apache-2.0")

            # CLI value used when not present in config file
            self.assertEqual(settings["creator"], "Person: Bob")

            # Default used when neither has it
            self.assertEqual(settings["copyright"], "NOASSERTION")
        finally:
            Path(cfg_path).unlink(missing_ok=True)

if __name__ == "__main__":
    unittest.main()
