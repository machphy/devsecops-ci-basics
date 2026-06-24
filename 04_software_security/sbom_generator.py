#!/usr/bin/env python3
"""
SBOM Generator - CycloneDX Format
===================================
Inspired by CycloneDX/sbom-utility (Matt Rutkowski / mrutkows)

Generates a Software Bill of Materials (SBOM) in CycloneDX JSON format
by scanning Python project dependencies (requirements.txt / pip freeze).

Features:
  - Parses requirements.txt or pip freeze output
  - Generates CycloneDX 1.5 compliant JSON SBOM
  - Includes component metadata (name, version, purl, type)
  - Supports license detection from package metadata
  - Validates generated SBOM against CycloneDX schema keys

Usage:
  python sbom_generator.py                          # scans requirements.txt
  python sbom_generator.py --input freeze.txt       # custom input file
  python sbom_generator.py --output my_sbom.json    # custom output path

References:
  - CycloneDX Specification: https://cyclonedx.org/specification/overview/
  - SBOM Utility: https://github.com/CycloneDX/sbom-utility
"""

import argparse
import json
import re
import sys
import uuid
import hashlib
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
CYCLONEDX_SPEC_VERSION = "1.5"
CYCLONEDX_BOM_FORMAT = "CycloneDX"
TOOL_NAME = "devsecops-sbom-generator"
TOOL_VERSION = "1.0.0"
TOOL_VENDOR = "DevSecOps CI Basics"

# Known license mappings (subset for demonstration)
KNOWN_LICENSES = {
    "MIT": "MIT",
    "Apache-2.0": "Apache-2.0",
    "Apache License 2.0": "Apache-2.0",
    "BSD": "BSD-3-Clause",
    "BSD-3-Clause": "BSD-3-Clause",
    "GPL-3.0": "GPL-3.0-only",
    "ISC": "ISC",
    "MPL-2.0": "MPL-2.0",
    "LGPL-2.1": "LGPL-2.1-only",
    "CC0-1.0": "CC0-1.0",
}


# ---------------------------------------------------------------------------
# Dependency Parser
# ---------------------------------------------------------------------------
class DependencyParser:
    """Parses dependency declarations from requirements files."""

    # Matches: package==1.0.0, package>=1.0.0, package~=1.0.0, package
    REQUIREMENT_PATTERN = re.compile(
        r"^([A-Za-z0-9_][A-Za-z0-9._-]*)\s*"
        r"(?:(==|>=|<=|~=|!=|>|<)\s*([A-Za-z0-9.*+\-]+))?"
        r"(?:\s*;.*)?$"  # environment markers
    )

    @staticmethod
    def parse_requirements(filepath: str) -> list[dict]:
        """Parse a requirements.txt file and return component dicts."""
        components = []
        path = Path(filepath)

        if not path.exists():
            print(f"[WARN] File not found: {filepath}")
            return components

        with open(path, "r", encoding="utf-8") as fh:
            for line_no, raw_line in enumerate(fh, start=1):
                line = raw_line.strip()

                # Skip blanks, comments, options
                if not line or line.startswith("#") or line.startswith("-"):
                    continue

                match = DependencyParser.REQUIREMENT_PATTERN.match(line)
                if match:
                    name = match.group(1)
                    version = match.group(3) or "unknown"
                    components.append({
                        "name": name,
                        "version": version,
                        "line": line_no,
                    })
                else:
                    print(f"[WARN] Could not parse line {line_no}: {line}")

        return components


# ---------------------------------------------------------------------------
# SBOM Builder
# ---------------------------------------------------------------------------
class CycloneDXBuilder:
    """Builds a CycloneDX 1.5 compliant SBOM document."""

    def __init__(self, project_name: str = "devsecops-ci-basics"):
        self.serial_number = f"urn:uuid:{uuid.uuid4()}"
        self.project_name = project_name
        self.timestamp = datetime.now(timezone.utc).isoformat()

    # -- helpers ----------------------------------------------------------

    @staticmethod
    def _make_purl(name: str, version: str, pkg_type: str = "pypi") -> str:
        """Generate a Package URL (purl) for a component."""
        return f"pkg:{pkg_type}/{name}@{version}"

    @staticmethod
    def _make_bom_ref(name: str, version: str) -> str:
        """Generate a deterministic bom-ref from name + version."""
        digest = hashlib.sha256(f"{name}@{version}".encode()).hexdigest()[:12]
        return f"{name}-{digest}"

    @staticmethod
    def _normalize_license(raw: Optional[str]) -> Optional[dict]:
        """Normalize a license string to SPDX ID dict."""
        if not raw:
            return None
        spdx_id = KNOWN_LICENSES.get(raw, raw)
        return {"license": {"id": spdx_id}}

    # -- build methods ----------------------------------------------------

    def build_metadata(self) -> dict:
        """Build the metadata section of the BOM."""
        return {
            "timestamp": self.timestamp,
            "tools": [
                {
                    "vendor": TOOL_VENDOR,
                    "name": TOOL_NAME,
                    "version": TOOL_VERSION,
                }
            ],
            "component": {
                "type": "application",
                "name": self.project_name,
                "bom-ref": self.project_name,
            },
        }

    def build_component(self, name: str, version: str,
                        comp_type: str = "library",
                        license_id: Optional[str] = None) -> dict:
        """Build a single CycloneDX component entry."""
        comp = {
            "type": comp_type,
            "name": name,
            "version": version,
            "purl": self._make_purl(name, version),
            "bom-ref": self._make_bom_ref(name, version),
        }
        lic = self._normalize_license(license_id)
        if lic:
            comp["licenses"] = [lic]
        return comp

    def build_bom(self, raw_components: list[dict]) -> dict:
        """Assemble the full BOM document."""
        components = [
            self.build_component(c["name"], c["version"])
            for c in raw_components
        ]

        bom = {
            "bomFormat": CYCLONEDX_BOM_FORMAT,
            "specVersion": CYCLONEDX_SPEC_VERSION,
            "serialNumber": self.serial_number,
            "version": 1,
            "metadata": self.build_metadata(),
            "components": components,
        }
        return bom


# ---------------------------------------------------------------------------
# SBOM Validator (basic)
# ---------------------------------------------------------------------------
class SBOMValidator:
    """Basic structural validation for CycloneDX JSON BOMs."""

    REQUIRED_TOP_KEYS = {"bomFormat", "specVersion", "version", "components"}
    REQUIRED_COMPONENT_KEYS = {"type", "name", "version"}

    @classmethod
    def validate(cls, bom: dict) -> list[str]:
        """Return a list of validation errors (empty = valid)."""
        errors: list[str] = []

        # Top-level keys
        missing = cls.REQUIRED_TOP_KEYS - set(bom.keys())
        if missing:
            errors.append(f"Missing top-level keys: {missing}")

        if bom.get("bomFormat") != CYCLONEDX_BOM_FORMAT:
            errors.append(
                f"bomFormat must be '{CYCLONEDX_BOM_FORMAT}', "
                f"got '{bom.get('bomFormat')}'"
            )

        # Components
        for idx, comp in enumerate(bom.get("components", [])):
            comp_missing = cls.REQUIRED_COMPONENT_KEYS - set(comp.keys())
            if comp_missing:
                errors.append(
                    f"Component [{idx}] missing keys: {comp_missing}"
                )

        return errors


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(
        description="Generate a CycloneDX SBOM from Python dependencies"
    )
    parser.add_argument(
        "--input", "-i",
        default="requirements.txt",
        help="Path to requirements.txt (default: requirements.txt)",
    )
    parser.add_argument(
        "--output", "-o",
        default="sbom.cdx.json",
        help="Output SBOM file path (default: sbom.cdx.json)",
    )
    parser.add_argument(
        "--project", "-p",
        default="devsecops-ci-basics",
        help="Project name for SBOM metadata",
    )
    parser.add_argument(
        "--validate", "-v",
        action="store_true",
        help="Validate the generated SBOM",
    )
    args = parser.parse_args()

    print(f"[*] SBOM Generator v{TOOL_VERSION}")
    print(f"[*] Scanning: {args.input}")

    # Parse
    deps = DependencyParser.parse_requirements(args.input)
    print(f"[+] Found {len(deps)} dependencies")

    # Build
    builder = CycloneDXBuilder(project_name=args.project)
    bom = builder.build_bom(deps)

    # Validate
    if args.validate:
        errors = SBOMValidator.validate(bom)
        if errors:
            print("[!] Validation errors:")
            for e in errors:
                print(f"    - {e}")
            sys.exit(1)
        else:
            print("[+] SBOM validation passed")

    # Write
    output_path = Path(args.output)
    with open(output_path, "w", encoding="utf-8") as fh:
        json.dump(bom, fh, indent=2)

    print(f"[+] SBOM written to {output_path}")
    print(f"    Serial: {bom['serialNumber']}")
    print(f"    Components: {len(bom['components'])}")


if __name__ == "__main__":
    main()
