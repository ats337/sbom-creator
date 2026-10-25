"""Command-line interface for SBOM Creator."""
import argparse
import sys
import os
from pathlib import Path

from sbom_creator.core import generate_sbom
from sbom_creator.formats import FORMATTERS
from sbom_creator.config import resolve_settings

def create_parser() -> argparse.ArgumentParser:
    supported_formats = sorted(list(set(FORMATTERS.keys())))
    parser = argparse.ArgumentParser(
        prog="sbom-creator",
        description="CLI tool to generate Software Bill of Materials (SBOM) for OS and multi-language projects.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Priority Order:
  Settings in config file > Command-line options > Default values

Examples:
  # Scan with config file
  python main.py -c config.json

  # Scan directory and override options via CLI
  python main.py -t ./my-app -o sbom.cdx.json --license MIT

  # Output in SPDX format with custom creator and version
  python main.py -t ./my-app -f spdx -v 1.2.0 --creator "Organization: Example Inc" -o sbom.spdx.json
"""
    )

    parser.add_argument(
        "target_pos",
        nargs="?",
        default=None,
        help="Target directory to scan (positional alternative to -t/--target)"
    )

    parser.add_argument(
        "-c", "--config",
        dest="config_path",
        default=None,
        help="Path to configuration file (.json or .toml). Config values take precedence over CLI options."
    )

    parser.add_argument(
        "-t", "--target",
        dest="target_opt",
        default=None,
        help="Target project directory to scan"
    )

    parser.add_argument(
        "-f", "--format",
        choices=supported_formats,
        default=None,
        help=f"SBOM output format (default: cyclonedx). Options: {', '.join(supported_formats)}"
    )

    parser.add_argument(
        "-o", "--output",
        default=None,
        help="Output file path (default: print to stdout)"
    )

    # Metadata customization
    parser.add_argument(
        "-n", "--name",
        default=None,
        help="Target project/system name in SBOM metadata (default: directory name)"
    )

    parser.add_argument(
        "-v", "--version-info",
        dest="version",
        default=None,
        help="Target project version (default: 'latest')"
    )

    parser.add_argument(
        "--description",
        default=None,
        help="Project description"
    )

    parser.add_argument(
        "--license",
        default=None,
        help="Declared/concluded license for target project (e.g. Apache-2.0, MIT)"
    )

    parser.add_argument(
        "--copyright",
        default=None,
        help="Copyright text for target project (default: 'NOASSERTION')"
    )

    parser.add_argument(
        "--creator",
        default=None,
        help="Creator identity (e.g. 'Organization: Example Inc' or 'Person: Alice')"
    )

    parser.add_argument(
        "--supplier",
        default=None,
        help="Supplier identity (e.g. 'Organization: Example Inc')"
    )

    parser.add_argument(
        "--download-location",
        default=None,
        help="Download URL for target project"
    )

    parser.add_argument(
        "--homepage",
        default=None,
        help="Homepage URL for target project"
    )

    parser.add_argument(
        "--namespace-prefix",
        default=None,
        help="SPDX documentNamespace prefix (default: 'https://spdx.org/spdxdocs')"
    )

    parser.add_argument(
        "--document-namespace",
        default=None,
        help="SPDX documentNamespace full URI (overrides namespace-prefix/name)"
    )

    parser.add_argument(
        "--serial-number",
        default=None,
        help="Document serial number (used by CycloneDX)"
    )

    # OS scan flags
    parser.add_argument(
        "--include-os",
        dest="include_os",
        action="store_true",
        default=None,
        help="Include host operating system and system packages in the SBOM"
    )

    parser.add_argument(
        "--os-only",
        dest="os_only",
        action="store_true",
        default=None,
        help="Only scan host operating system and system packages"
    )

    parser.add_argument(
        "--no-os-packages",
        dest="no_os_packages",
        action="store_true",
        default=None,
        help="When scanning OS, skip package manager scan"
    )

    return parser

def main() -> int:
    parser = create_parser()
    args = parser.parse_args()

    # Collect CLI arguments that were explicitly provided
    cli_args = {}
    target_val = args.target_opt or args.target_pos
    if target_val is not None:
        cli_args["target"] = target_val
    if args.format is not None:
        cli_args["format"] = args.format
    if args.output is not None:
        cli_args["output"] = args.output
    if args.name is not None:
        cli_args["name"] = args.name
    if args.version is not None:
        cli_args["version"] = args.version
    if args.description is not None:
        cli_args["description"] = args.description
    if args.license is not None:
        cli_args["license"] = args.license
    if args.copyright is not None:
        cli_args["copyright"] = args.copyright
    if args.creator is not None:
        cli_args["creator"] = args.creator
    if args.supplier is not None:
        cli_args["supplier"] = args.supplier
    if args.download_location is not None:
        cli_args["download_location"] = args.download_location
    if args.homepage is not None:
        cli_args["homepage"] = args.homepage
    if args.namespace_prefix is not None:
        cli_args["namespace_prefix"] = args.namespace_prefix
    if args.serial_number is not None:
        cli_args["serial_number"] = args.serial_number
    if args.include_os is not None:
        cli_args["include_os"] = args.include_os
    if args.os_only is not None:
        cli_args["os_only"] = args.os_only
    if args.no_os_packages is not None:
        cli_args["scan_os_packages"] = not args.no_os_packages

    try:
        # Resolve settings: Config file > CLI options > Default values
        settings = resolve_settings(cli_args=cli_args, config_file_path=args.config_path)

        output_str = generate_sbom(settings=settings)

        out_file = settings.get("output")
        if out_file:
            out_path = Path(out_file).resolve()
            out_path.parent.mkdir(parents=True, exist_ok=True)
            with open(out_path, "w", encoding="utf-8") as f:
                f.write(output_str)
            print(f"[+] SBOM successfully written to: {out_path}", file=sys.stderr)
        else:
            print(output_str)

        return 0
    except Exception as e:
        print(f"[-] Error generating SBOM: {e}", file=sys.stderr)
        return 1

if __name__ == "__main__":
    sys.exit(main())
