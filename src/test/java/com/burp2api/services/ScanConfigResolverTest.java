package com.burp2api.services;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * Ticket #15: the default audit config ({@code BURP2API_SCAN_CONFIG}) resolves to
 * either a library NAME (NamedConfiguration downstream) or an inline
 * CustomConfiguration built from a config JSON file exported from the Burp UI, so
 * {@code backend=auto} works against an empty configuration library. All offline.
 */
class ScanConfigResolverTest {

    @Test
    void blankConfigResolvesToNullSoBurpsDefaultConfigIsUsed() throws IOException {
        assertThat(ScanConfigResolver.entryFor(null, null)).isNull();
        assertThat(ScanConfigResolver.entryFor("   ", null)).isNull();
        assertThat(ScanConfigResolver.resolveDefault("")).isNull();
    }

    @Test
    void plainNameStaysANameAndIsTrimmed() throws IOException {
        // A non-path value with no matching file is a library config name.
        assertThat(ScanConfigResolver.entryFor("b2a-light-fuzz", null))
            .isEqualTo("b2a-light-fuzz");
        assertThat(ScanConfigResolver.resolveDefault("  b2a-light-fuzz  "))
            .isEqualTo("b2a-light-fuzz");
    }

    @Test
    void fileContentsBecomeAnInlineCustomConfiguration() {
        String exported = "{\"audit\":{\"checks\":[123,456]}}";
        Object entry = ScanConfigResolver.entryFor("b2a-light-fuzz", exported);
        assertThat(entry).isInstanceOf(Map.class);
        @SuppressWarnings("unchecked")
        Map<String, Object> map = (Map<String, Object>) entry;
        assertThat(map).containsEntry("type", "CustomConfiguration");
        assertThat(map).containsEntry("config", exported);
    }

    @Test
    void resolveDefaultReadsAnExistingFileAsCustomConfiguration(@TempDir Path dir)
            throws IOException {
        String exported = "{\"audit\":{\"name\":\"b2a-light-fuzz\"}}";
        Path file = dir.resolve("b2a-light-fuzz.json");
        Files.writeString(file, exported);

        Object entry = ScanConfigResolver.resolveDefault(file.toString());

        assertThat(entry).isInstanceOf(Map.class);
        @SuppressWarnings("unchecked")
        Map<String, Object> map = (Map<String, Object>) entry;
        assertThat(map).containsEntry("type", "CustomConfiguration");
        assertThat(map).containsEntry("config", exported);
    }

    @Test
    void customConfigurationEntryFlowsThroughRestScanMapperUnchanged() {
        // RestScanMapper passes pre-shaped maps straight into scan_configurations,
        // so a resolved CustomConfiguration reaches Burp's REST /scan as-is.
        Object entry = ScanConfigResolver.entryFor("ignored", "{\"exported\":true}");
        Map<String, Object> body = RestScanMapper.buildScanBody(
            java.util.List.of("http://t/x?q=1"),
            java.util.List.of(entry),
            "Default resource pool",
            java.util.List.of("http://t/x?q=1"));

        @SuppressWarnings("unchecked")
        java.util.List<Map<String, Object>> configs =
            (java.util.List<Map<String, Object>>) body.get("scan_configurations");
        assertThat(configs).hasSize(1);
        assertThat(configs.get(0)).containsEntry("type", "CustomConfiguration");
        assertThat(configs.get(0)).containsEntry("config", "{\"exported\":true}");
    }
}
