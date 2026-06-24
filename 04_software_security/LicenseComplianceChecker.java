import java.io.*;
import java.nio.file.*;
import java.util.*;
import java.util.regex.*;

/**
 * LicenseComplianceChecker - Software License Policy Enforcement
 * ================================================================
 * Inspired by Matt Rutkowski's (mrutkows) CycloneDX license-scanner project.
 *
 * Checks CycloneDX SBOM components against a configurable license policy.
 * Flags denied licenses, warns on unknown licenses, and generates a compliance report.
 *
 * Usage:
 *   javac LicenseComplianceChecker.java
 *   java LicenseComplianceChecker sbom.cdx.json
 *   java LicenseComplianceChecker sbom.cdx.json --strict
 */
public class LicenseComplianceChecker {

    // --- License policy categories ---
    static final Set<String> ALLOWED = new LinkedHashSet<>(Arrays.asList(
        "MIT", "Apache-2.0", "BSD-2-Clause", "BSD-3-Clause",
        "ISC", "CC0-1.0", "CC-BY-4.0", "Unlicense", "PSF-2.0",
        "MPL-2.0", "Zlib", "BSL-1.0"
    ));

    static final Set<String> DENIED = new LinkedHashSet<>(Arrays.asList(
        "GPL-3.0-only", "GPL-3.0-or-later",
        "AGPL-3.0-only", "AGPL-3.0-or-later",
        "SSPL-1.0", "EUPL-1.2"
    ));

    static final Set<String> COPYLEFT_WEAK = new LinkedHashSet<>(Arrays.asList(
        "LGPL-2.1-only", "LGPL-2.1-or-later",
        "LGPL-3.0-only", "LGPL-3.0-or-later",
        "EPL-2.0", "CPL-1.0"
    ));

    enum Status { PASS, FAIL, WARN }
    enum Severity { CRITICAL, HIGH, MEDIUM, LOW, INFO }

    static class Finding {
        Status status;
        Severity severity;
        String component;
        String license;
        String message;
        String recommendation;

        Finding(Status s, Severity sev, String comp, String lic, String msg, String rec) {
            this.status = s; this.severity = sev; this.component = comp;
            this.license = lic; this.message = msg; this.recommendation = rec;
        }
    }

    // --- Lightweight JSON helpers (same as SBOMParser) ---
    static String extractStr(String json, String key) {
        Pattern p = Pattern.compile("\"" + Pattern.quote(key) + "\"\\s*:\\s*\"([^\"]*?)\"");
        Matcher m = p.matcher(json);
        return m.find() ? m.group(1) : null;
    }

    static String extractBlock(String json, int start, char open, char close) {
        int depth = 0, i = start;
        while (i < json.length()) {
            if (json.charAt(i) == open) depth++;
            else if (json.charAt(i) == close) { depth--; if (depth == 0) return json.substring(start, i + 1); }
            i++;
        }
        return json.substring(start);
    }

    static String extractArray(String json, String key) {
        String search = "\"" + key + "\"";
        int idx = json.indexOf(search);
        if (idx < 0) return null;
        int bs = json.indexOf('[', idx + search.length());
        if (bs < 0) return null;
        return extractBlock(json, bs, '[', ']');
    }

    static List<String> splitArray(String arrJson) {
        List<String> items = new ArrayList<>();
        if (arrJson == null || arrJson.length() < 2) return items;
        String inner = arrJson.substring(1, arrJson.length() - 1).trim();
        if (inner.isEmpty()) return items;
        int depth = 0, start = 0;
        for (int i = 0; i < inner.length(); i++) {
            char c = inner.charAt(i);
            if (c == '{' || c == '[') depth++;
            else if (c == '}' || c == ']') depth--;
            else if (c == ',' && depth == 0) { items.add(inner.substring(start, i).trim()); start = i + 1; }
        }
        String last = inner.substring(start).trim();
        if (!last.isEmpty()) items.add(last);
        return items;
    }

    // --- Check a single component ---
    static List<Finding> checkComponent(String compJson, boolean strict) {
        List<Finding> findings = new ArrayList<>();
        String name = extractStr(compJson, "name");
        String version = extractStr(compJson, "version");
        String display = (name != null ? name : "?") + "@" + (version != null ? version : "?");

        String licensesArr = extractArray(compJson, "licenses");
        if (licensesArr == null || splitArray(licensesArr).isEmpty()) {
            findings.add(new Finding(
                strict ? Status.FAIL : Status.WARN,
                strict ? Severity.HIGH : Severity.MEDIUM,
                display, "(none)",
                "No license declared for component",
                "Add license metadata to this dependency"
            ));
            return findings;
        }

        for (String licBlock : splitArray(licensesArr)) {
            String licId = extractStr(licBlock, "id");
            if (licId == null) licId = extractStr(licBlock, "name");
            if (licId == null) licId = "UNKNOWN";

            if (DENIED.contains(licId)) {
                findings.add(new Finding(Status.FAIL, Severity.CRITICAL, display, licId,
                    "License '" + licId + "' is DENIED by policy",
                    "Replace with a permissive-licensed alternative"));
            } else if (COPYLEFT_WEAK.contains(licId)) {
                findings.add(new Finding(Status.WARN, Severity.MEDIUM, display, licId,
                    "Weak copyleft license '" + licId + "' requires legal review",
                    "Verify compliance with linking/distribution requirements"));
            } else if (ALLOWED.contains(licId)) {
                findings.add(new Finding(Status.PASS, Severity.INFO, display, licId,
                    "License '" + licId + "' is ALLOWED", null));
            } else {
                findings.add(new Finding(Status.WARN, Severity.MEDIUM, display, licId,
                    "License '" + licId + "' is not in any policy list",
                    "Review and classify this license"));
            }
        }
        return findings;
    }

    // --- Print report ---
    static void printReport(List<Finding> findings, String file) {
        Map<Status, String> icons = Map.of(Status.PASS, "✅", Status.FAIL, "❌", Status.WARN, "⚠️");

        boolean overallPass = findings.stream().noneMatch(f -> f.status == Status.FAIL);
        long pass = findings.stream().filter(f -> f.status == Status.PASS).count();
        long fail = findings.stream().filter(f -> f.status == Status.FAIL).count();
        long warn = findings.stream().filter(f -> f.status == Status.WARN).count();

        System.out.println("╔══════════════════════════════════════════════════════════════╗");
        System.out.println("║           License Compliance Report                         ║");
        System.out.println("╠══════════════════════════════════════════════════════════════╣");
        System.out.printf("║  File   : %-49s║%n", file.length() > 49 ? file.substring(0, 46) + "..." : file);
        System.out.printf("║  Result : %-49s║%n", overallPass ? "✅ COMPLIANT" : "❌ NON-COMPLIANT");
        System.out.printf("║  Stats  : %-49s║%n",
            String.format("✅ %d  ❌ %d  ⚠️ %d", pass, fail, warn));
        System.out.println("╚══════════════════════════════════════════════════════════════╝");
        System.out.println();

        // Show failures and warnings first
        for (Status s : new Status[]{Status.FAIL, Status.WARN, Status.PASS}) {
            for (Finding f : findings) {
                if (f.status != s) continue;
                System.out.printf("  %s [%-8s] %s  |  %s%n",
                    icons.get(f.status), f.severity, f.component, f.license);
                System.out.printf("     %s%n", f.message);
                if (f.recommendation != null)
                    System.out.printf("     → %s%n", f.recommendation);
            }
        }

        System.out.println();
        System.out.println(overallPass
            ? "  ✅ All components comply with license policy."
            : "  ❌ License policy violations detected! Review findings above.");
    }

    // --- Main ---
    public static void main(String[] args) {
        if (args.length < 1) {
            System.out.println("Usage: java LicenseComplianceChecker <sbom.cdx.json> [--strict]");
            System.exit(1);
        }

        String filePath = args[0];
        boolean strict = Arrays.asList(args).contains("--strict");

        try {
            String json = new String(Files.readAllBytes(Paths.get(filePath)), "UTF-8");
            String compArray = extractArray(json, "components");
            List<Finding> findings = new ArrayList<>();

            if (compArray != null) {
                for (String compJson : splitArray(compArray)) {
                    findings.addAll(checkComponent(compJson, strict));
                }
            }

            System.out.printf("[*] License Compliance Checker%s%n", strict ? " (STRICT MODE)" : "");
            System.out.printf("[*] Checking: %s%n%n", filePath);
            printReport(findings, filePath);

            boolean passed = findings.stream().noneMatch(f -> f.status == Status.FAIL);
            System.exit(passed ? 0 : 1);

        } catch (IOException e) {
            System.err.println("[ERROR] Cannot read file: " + e.getMessage());
            System.exit(1);
        }
    }
}
