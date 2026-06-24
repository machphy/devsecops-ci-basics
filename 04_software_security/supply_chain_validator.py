#!/usr/bin/env python3
"""
Supply Chain Security Validator
Inspired by Matt Rutkowski's (mrutkows) work on OSSCS at IBM and CycloneDX.

Validates SBOM integrity, license compliance, and known vulnerabilities.

Usage:
  python supply_chain_validator.py --sbom sbom.cdx.json
  python supply_chain_validator.py --sbom sbom.cdx.json --check-vulns
"""

import argparse, json, sys
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Optional

class Severity(Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

class CheckStatus(Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    WARN = "WARN"

@dataclass
class Finding:
    check: str
    status: CheckStatus
    severity: Severity
    message: str
    component: Optional[str] = None
    recommendation: Optional[str] = None

@dataclass
class ValidationReport:
    sbom_file: str
    findings: list = field(default_factory=list)

    @property
    def passed(self):
        return not any(f.status == CheckStatus.FAIL for f in self.findings)

    @property
    def summary(self):
        return {s.value: sum(1 for f in self.findings if f.status == s) for s in CheckStatus}

DEFAULT_POLICY = {
    "allowed": ["MIT","Apache-2.0","BSD-2-Clause","BSD-3-Clause","ISC","CC0-1.0","Unlicense"],
    "denied": ["GPL-3.0-only","AGPL-3.0-only","SSPL-1.0"],
}

VULN_DB = {
    "requests":     [{"cve":"CVE-2023-32681","sev":"MEDIUM","fix":"2.31.0","desc":"Proxy-Auth header leak"}],
    "urllib3":      [{"cve":"CVE-2023-45803","sev":"MEDIUM","fix":"2.0.7","desc":"Body not stripped on redirect"}],
    "cryptography": [{"cve":"CVE-2024-26130","sev":"HIGH","fix":"42.0.4","desc":"NULL deref in PKCS#12"}],
    "flask":        [{"cve":"CVE-2023-30861","sev":"HIGH","fix":"2.3.2","desc":"Session cookie on every response"}],
    "pillow":       [{"cve":"CVE-2023-50447","sev":"CRITICAL","fix":"10.2.0","desc":"RCE via crafted image"}],
    "jinja2":       [{"cve":"CVE-2024-22195","sev":"MEDIUM","fix":"3.1.3","desc":"XSS via xmlattr filter"}],
}

def _ver_lt(v1, v2):
    try:
        return [int(x) for x in v1.split(".")] < [int(x) for x in v2.split(".")]
    except (ValueError, AttributeError):
        return False

def validate_structure(bom):
    findings = []
    if bom.get("bomFormat") != "CycloneDX":
        findings.append(Finding("struct.format", CheckStatus.FAIL, Severity.CRITICAL,
                                f"Invalid bomFormat: '{bom.get('bomFormat')}'"))
    else:
        findings.append(Finding("struct.format", CheckStatus.PASS, Severity.INFO, "bomFormat OK"))

    if not bom.get("specVersion"):
        findings.append(Finding("struct.specVersion", CheckStatus.FAIL, Severity.HIGH, "Missing specVersion"))

    if not bom.get("serialNumber"):
        findings.append(Finding("struct.serial", CheckStatus.WARN, Severity.MEDIUM,
                                "Missing serialNumber", recommendation="Add urn:uuid:..."))

    if not bom.get("components"):
        findings.append(Finding("struct.components", CheckStatus.WARN, Severity.MEDIUM, "Zero components"))

    for c in bom.get("components", []):
        if not c.get("purl"):
            findings.append(Finding("struct.purl", CheckStatus.WARN, Severity.MEDIUM,
                                    "Missing purl", component=c.get("name")))
    return findings

def validate_licenses(bom, policy=None):
    pol = policy or DEFAULT_POLICY
    findings = []
    allowed, denied = set(pol["allowed"]), set(pol["denied"])

    for comp in bom.get("components", []):
        name = comp.get("name", "?")
        for lic_e in comp.get("licenses", []):
            sid = lic_e.get("license", {}).get("id", "")
            if sid in denied:
                findings.append(Finding("license.denied", CheckStatus.FAIL, Severity.CRITICAL,
                                        f"'{sid}' DENIED", component=name))
            elif sid in allowed:
                findings.append(Finding("license.ok", CheckStatus.PASS, Severity.INFO,
                                        f"'{sid}' allowed", component=name))
            else:
                findings.append(Finding("license.unknown", CheckStatus.WARN, Severity.MEDIUM,
                                        f"'{sid}' not in policy", component=name))
    return findings

def validate_vulns(bom):
    findings = []
    for comp in bom.get("components", []):
        name, ver = comp.get("name","").lower(), comp.get("version","unknown")
        for v in VULN_DB.get(name, []):
            if ver == "unknown" or _ver_lt(ver, v["fix"]):
                findings.append(Finding("vuln.cve", CheckStatus.FAIL, Severity[v["sev"]],
                    f"{v['cve']}: {v['desc']} (fix>={v['fix']})", component=f"{name}@{ver}",
                    recommendation=f"Upgrade to >= {v['fix']}"))
            else:
                findings.append(Finding("vuln.cve", CheckStatus.PASS, Severity.INFO,
                    f"{v['cve']} patched", component=f"{name}@{ver}"))
    return findings

def print_report(report):
    icons = {CheckStatus.PASS:"✅", CheckStatus.FAIL:"❌", CheckStatus.WARN:"⚠️"}
    print("=" * 65)
    print("  Supply Chain Security Validation Report")
    print("=" * 65)
    print(f"  SBOM   : {report.sbom_file}")
    print(f"  Result : {'✅ PASS' if report.passed else '❌ FAIL'}")
    print(f"  Summary: {report.summary}")
    print("-" * 65)
    for f in report.findings:
        c = f" [{f.component}]" if f.component else ""
        print(f"  {icons[f.status]} [{f.severity.value:8s}] {f.check}{c}")
        print(f"     {f.message}")
        if f.recommendation:
            print(f"     → {f.recommendation}")
    print("=" * 65)

def main():
    ap = argparse.ArgumentParser(description="Supply chain SBOM validator")
    ap.add_argument("--sbom", "-s", required=True)
    ap.add_argument("--policy", "-p")
    ap.add_argument("--check-vulns", action="store_true")
    ap.add_argument("--json-output", "-j")
    args = ap.parse_args()

    bom = json.loads(Path(args.sbom).read_text())
    policy = json.loads(Path(args.policy).read_text()) if args.policy else None

    report = ValidationReport(args.sbom)
    report.findings.extend(validate_structure(bom))
    report.findings.extend(validate_licenses(bom, policy))
    if args.check_vulns:
        report.findings.extend(validate_vulns(bom))

    print_report(report)
    if args.json_output:
        with open(args.json_output, "w") as f:
            json.dump({"file": report.sbom_file, "pass": report.passed,
                       "summary": report.summary,
                       "findings": [{"check":x.check,"status":x.status.value,
                         "severity":x.severity.value,"msg":x.message,
                         "component":x.component} for x in report.findings]}, f, indent=2)
    sys.exit(0 if report.passed else 1)

if __name__ == "__main__":
    main()
