import java.io.*;
import java.nio.file.*;
import java.security.MessageDigest;
import java.util.*;
import java.util.regex.*;

/**
 * SBOMParser - CycloneDX SBOM Parser in Java
 * ============================================
 * Inspired by Matt Rutkowski's (mrutkows) CycloneDX/sbom-utility project.
 *
 * Parses CycloneDX JSON SBOMs and extracts component information including:
 *   - Component name, version, type, purl
 *   - License identifiers
 *   - Dependency relationships
 *
 * Usage:
 *   javac SBOMParser.java
 *   java SBOMParser sbom.cdx.json
 *   java SBOMParser sbom.cdx.json --summary
 *   java SBOMParser sbom.cdx.json --search requests
 */
public class SBOMParser {

    // --- Data model ---
    static class Component {
        String type, name, version, purl, bomRef;
        List<String> licenses = new ArrayList<>();

        @Override
        public String toString() {
            return String.format("%-30s %-12s %-10s %s", name, version, type,
                    licenses.isEmpty() ? "(no license)" : String.join(", ", licenses));
        }
    }

    static class BOM {
        String bomFormat, specVersion, serialNumber;
        int version;
        String metadataTimestamp;
        String metadataComponentName;
        List<Component> components = new ArrayList<>();
    }

    // --- Lightweight JSON value extractor (no external deps) ---
    static String extractString(String json, String key) {
        Pattern p = Pattern.compile("\"" + Pattern.quote(key) + "\"\\s*:\\s*\"([^\"]*?)\"");
        Matcher m = p.matcher(json);
        return m.find() ? m.group(1) : null;
    }

    static int extractInt(String json, String key, int fallback) {
        Pattern p = Pattern.compile("\"" + Pattern.quote(key) + "\"\\s*:\\s*(\\d+)");
        Matcher m = p.matcher(json);
        return m.find() ? Integer.parseInt(m.group(1)) : fallback;
    }

    // Find balanced braces starting from an index
    static String extractBlock(String json, int start, char open, char close) {
        int depth = 0;
        int i = start;
        while (i < json.length()) {
            if (json.charAt(i) == open) depth++;
            else if (json.charAt(i) == close) { depth--; if (depth == 0) return json.substring(start, i + 1); }
            i++;
        }
        return json.substring(start);
    }

    // Split a JSON array into its top-level elements
    static List<String> splitArray(String arrayJson) {
        List<String> items = new ArrayList<>();
        if (arrayJson == null || arrayJson.length() < 2) return items;
        String inner = arrayJson.substring(1, arrayJson.length() - 1).trim();
        if (inner.isEmpty()) return items;

        int depth = 0;
        int start = 0;
        for (int i = 0; i < inner.length(); i++) {
            char c = inner.charAt(i);
            if (c == '{' || c == '[') depth++;
            else if (c == '}' || c == ']') depth--;
            else if (c == ',' && depth == 0) {
                items.add(inner.substring(start, i).trim());
                start = i + 1;
            }
        }
        String last = inner.substring(start).trim();
        if (!last.isEmpty()) items.add(last);
        return items;
    }

    // Extract a JSON array value by key
    static String extractArray(String json, String key) {
        String search = "\"" + key + "\"";
        int idx = json.indexOf(search);
        if (idx < 0) return null;
        int bracketStart = json.indexOf('[', idx + search.length());
        if (bracketStart < 0) return null;
        return extractBlock(json, bracketStart, '[', ']');
    }

    // --- Parse a component JSON block ---
    static Component parseComponent(String json) {
        Component c = new Component();
        c.type = extractString(json, "type");
        c.name = extractString(json, "name");
        c.version = extractString(json, "version");
        c.purl = extractString(json, "purl");
        c.bomRef = extractString(json, "bom-ref");

        String licensesArr = extractArray(json, "licenses");
        if (licensesArr != null) {
            for (String licBlock : splitArray(licensesArr)) {
                String id = extractString(licBlock, "id");
                if (id != null) c.licenses.add(id);
                else {
                    String name = extractString(licBlock, "name");
                    if (name != null) c.licenses.add(name);
                }
            }
        }
        return c;
    }

    // --- Parse the full BOM ---
    static BOM parseBOM(String json) {
        BOM bom = new BOM();
        bom.bomFormat = extractString(json, "bomFormat");
        bom.specVersion = extractString(json, "specVersion");
        bom.serialNumber = extractString(json, "serialNumber");
        bom.version = extractInt(json, "version", 1);
        bom.metadataTimestamp = extractString(json, "timestamp");

        // Parse components
        String compArray = extractArray(json, "components");
        if (compArray != null) {
            for (String compJson : splitArray(compArray)) {
                bom.components.add(parseComponent(compJson));
            }
        }
        return bom;
    }

    // --- Compute SHA-256 hash of the SBOM file ---
    static String sha256(byte[] data) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] hash = md.digest(data);
            StringBuilder sb = new StringBuilder();
            for (byte b : hash) sb.append(String.format("%02x", b));
            return sb.toString();
        } catch (Exception e) {
            return "error";
        }
    }

    // --- Print summary ---
    static void printSummary(BOM bom) {
        System.out.println("╔══════════════════════════════════════════════════════════════╗");
        System.out.println("║             CycloneDX SBOM Summary                         ║");
        System.out.println("╠══════════════════════════════════════════════════════════════╣");
        System.out.printf("║  Format      : %-44s║%n", bom.bomFormat);
        System.out.printf("║  Spec Version: %-44s║%n", bom.specVersion);
        System.out.printf("║  Serial      : %-44s║%n",
                bom.serialNumber != null ? bom.serialNumber.substring(0, Math.min(44, bom.serialNumber.length())) : "N/A");
        System.out.printf("║  Timestamp   : %-44s║%n",
                bom.metadataTimestamp != null ? bom.metadataTimestamp : "N/A");
        System.out.printf("║  Components  : %-44d║%n", bom.components.size());
        System.out.println("╚══════════════════════════════════════════════════════════════╝");

        // License distribution
        Map<String, Integer> licCount = new TreeMap<>();
        int noLicense = 0;
        for (Component c : bom.components) {
            if (c.licenses.isEmpty()) { noLicense++; continue; }
            for (String l : c.licenses) licCount.merge(l, 1, Integer::sum);
        }

        System.out.println("\n  License Distribution:");
        for (var e : licCount.entrySet())
            System.out.printf("    %-25s %d component(s)%n", e.getKey(), e.getValue());
        if (noLicense > 0)
            System.out.printf("    %-25s %d component(s)%n", "(no license)", noLicense);

        // Type distribution
        Map<String, Integer> typeCount = new TreeMap<>();
        for (Component c : bom.components)
            typeCount.merge(c.type != null ? c.type : "unknown", 1, Integer::sum);

        System.out.println("\n  Component Types:");
        for (var e : typeCount.entrySet())
            System.out.printf("    %-25s %d%n", e.getKey(), e.getValue());
    }

    // --- Print all components ---
    static void printComponents(BOM bom) {
        System.out.printf("%-4s %-30s %-12s %-10s %s%n", "#", "NAME", "VERSION", "TYPE", "LICENSE");
        System.out.println("-".repeat(80));
        int i = 1;
        for (Component c : bom.components)
            System.out.printf("%-4d %s%n", i++, c);
    }

    // --- Search components ---
    static void searchComponents(BOM bom, String query) {
        String q = query.toLowerCase();
        List<Component> matches = new ArrayList<>();
        for (Component c : bom.components)
            if ((c.name != null && c.name.toLowerCase().contains(q)) ||
                (c.purl != null && c.purl.toLowerCase().contains(q)))
                matches.add(c);

        System.out.printf("Search results for '%s': %d match(es)%n%n", query, matches.size());
        for (Component c : matches)
            System.out.printf("  • %s@%s  [%s]  %s%n", c.name, c.version, c.type,
                    c.purl != null ? c.purl : "");
    }

    // --- Main ---
    public static void main(String[] args) {
        if (args.length < 1) {
            System.out.println("Usage: java SBOMParser <sbom.cdx.json> [--summary|--search <term>]");
            System.exit(1);
        }

        String filePath = args[0];
        boolean summary = false;
        String searchTerm = null;

        for (int i = 1; i < args.length; i++) {
            if ("--summary".equals(args[i])) summary = true;
            if ("--search".equals(args[i]) && i + 1 < args.length) searchTerm = args[++i];
        }

        try {
            byte[] raw = Files.readAllBytes(Paths.get(filePath));
            String json = new String(raw, "UTF-8");
            String hash = sha256(raw);

            System.out.printf("[*] Parsing: %s (SHA-256: %s)%n%n", filePath, hash.substring(0, 16) + "...");

            BOM bom = parseBOM(json);

            if (searchTerm != null) {
                searchComponents(bom, searchTerm);
            } else if (summary) {
                printSummary(bom);
            } else {
                printSummary(bom);
                System.out.println();
                printComponents(bom);
            }

        } catch (IOException e) {
            System.err.println("[ERROR] Cannot read file: " + e.getMessage());
            System.exit(1);
        }
    }
}
