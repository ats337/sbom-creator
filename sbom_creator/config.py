"""Configuration loading and merging logic.

Priority order (as requested):
1. Config file values (highest priority)
2. CLI arguments (medium priority)
3. Default values (lowest priority)
"""
import json
from pathlib import Path
from typing import Dict, Any, Optional

try:
    import tomllib  # Python 3.11+
except ImportError:
    tomllib = None

# Default values for all configurable elements
DEFAULT_CONFIG: Dict[str, Any] = {
    "target": ".",
    "format": "cyclonedx",
    "output": None,
    "name": "",
    "version": "latest",
    "description": None,
    "license": None,
    "copyright": "NOASSERTION",
    "creator": None,
    "supplier": None,
    "download_location": "NOASSERTION",
    "homepage": None,
    "tool_name": "sbom-creator",
    "tool_version": "0.1.0",
    "namespace_prefix": "https://spdx.org/spdxdocs",
    "document_namespace": None,
    "serial_number": None,
    "include_os": False,
    "os_only": False,
    "scan_os_packages": True,
    "component_overrides": {},
}

def load_config_file(config_path: str) -> Dict[str, Any]:
    """Load configuration from JSON or TOML file."""
    p = Path(config_path).resolve()
    if not p.is_file():
        raise FileNotFoundError(f"Configuration file not found: {config_path}")

    with open(p, "rb") as f:
        content = f.read()

    # Determine file format by extension or attempt json then toml
    ext = p.suffix.lower()
    if ext == ".toml":
        if tomllib is None:
            raise RuntimeError("TOML configuration requires Python 3.11+ (tomllib)")
        return tomllib.loads(content.decode("utf-8"))
    else:
        # Default to JSON
        try:
            return json.loads(content.decode("utf-8"))
        except json.JSONDecodeError as e:
            if tomllib is not None and ext in (".toml", ".conf", ".ini"):
                try:
                    return tomllib.loads(content.decode("utf-8"))
                except Exception:
                    pass
            raise ValueError(f"Failed to parse config file as JSON ({config_path}): {e}")

def resolve_settings(
    cli_args: Dict[str, Any],
    config_file_path: Optional[str] = None
) -> Dict[str, Any]:
    """
    Resolve final settings according to strict priority:
    1. Config file values (overrides CLI)
    2. Command-line values (if not in config file)
    3. Default values (fallback)
    """
    config_file_values: Dict[str, Any] = {}
    if config_file_path:
        config_file_values = load_config_file(config_file_path)

    final_settings: Dict[str, Any] = {}

    for key, default_val in DEFAULT_CONFIG.items():
        # 1. Highest priority: Config file
        if key in config_file_values and config_file_values[key] is not None:
            final_settings[key] = config_file_values[key]
        # 2. Medium priority: CLI argument (if explicitly provided and not None)
        elif key in cli_args and cli_args[key] is not None:
            final_settings[key] = cli_args[key]
        # 3. Lowest priority: Default value
        else:
            final_settings[key] = default_val

    return final_settings
