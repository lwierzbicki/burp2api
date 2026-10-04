package com.burp2api.services;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Resolve the default audit configuration ({@code BURP2API_SCAN_CONFIG}) into a
 * {@code scan_configurations} entry for the Burp built-in REST API.
 *
 * <p>Ticket #15: the value may be either a library config <b>name</b>
 * (e.g. {@code b2a-light-fuzz}, resolved by Burp against its configuration
 * library) or a <b>path</b> to a config JSON file exported once from the Burp UI
 * (the config library is not authorable over any API). When it is a readable
 * file, the exported JSON is shipped inline as a {@code CustomConfiguration} so
 * {@code backend=auto} works on a fresh install with an <b>empty</b> library —
 * no pre-existing library entry required.
 *
 * <p>Pure decision logic ({@link #entryFor}) is separated from filesystem access
 * ({@link #resolveDefault}) so it can be unit-tested offline. No HTTP, no Burp.
 */
public final class ScanConfigResolver {

    private ScanConfigResolver() {
    }

    /** Wrap an exported audit-config JSON string as an inline {@code CustomConfiguration} entry. */
    public static Map<String, Object> customConfiguration(String exportedJson) {
        Map<String, Object> entry = new LinkedHashMap<>();
        entry.put("type", "CustomConfiguration");
        entry.put("config", exportedJson);
        return entry;
    }

    /**
     * Pure decision: given the configured default scan config and, when it named a
     * readable file, that file's contents, return the {@code scan_configurations}
     * entry. Non-null {@code fileContents} yields an inline {@code CustomConfiguration}
     * map; otherwise the plain trimmed name string (a {@code NamedConfiguration}
     * downstream). Returns {@code null} when the config is blank so the caller can
     * fall back to Burp's default config.
     */
    public static Object entryFor(String scanConfig, String fileContents) {
        if (scanConfig == null || scanConfig.trim().isEmpty()) {
            return null;
        }
        if (fileContents != null) {
            return customConfiguration(fileContents);
        }
        return scanConfig.trim();
    }

    /**
     * Filesystem wrapper around {@link #entryFor}: if {@code scanConfig} points to an
     * existing regular file, read it (UTF-8) and return an inline
     * {@code CustomConfiguration}; otherwise return the trimmed name. Blank input
     * returns {@code null} (Burp's default config).
     *
     * @throws IOException if the value names an existing file that cannot be read
     */
    public static Object resolveDefault(String scanConfig) throws IOException {
        if (scanConfig == null || scanConfig.trim().isEmpty()) {
            return null;
        }
        String trimmed = scanConfig.trim();
        Path path = Path.of(trimmed);
        String contents = null;
        if (Files.isRegularFile(path)) {
            contents = Files.readString(path);
        }
        return entryFor(trimmed, contents);
    }
}
