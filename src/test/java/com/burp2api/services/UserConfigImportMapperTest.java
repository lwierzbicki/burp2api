package com.burp2api.services;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.JsonNode;
import java.util.List;
import org.junit.jupiter.api.Test;

/**
 * Ticket #14: pure mapping for the user-options import endpoint — unwrap the
 * export-shaped wrapper, validate the payload is a non-empty JSON object, and
 * surface the imported top-level sections. Mirrors
 * {@link ProjectConfigImportMapperTest}. No Burp, no I/O.
 */
class UserConfigImportMapperTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private JsonNode parse(String json) {
        try {
            return MAPPER.readTree(json);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    @Test
    void unwrapsTheExportShapedWrapper() throws Exception {
        // GET /config/user-config returns {"user_configuration": {...}, ...};
        // a round-tripped POST of that must import the inner object only.
        JsonNode body = parse("{\"user_configuration\":{\"user_options\":"
            + "{\"rest_api\":{\"running\":true}}},\"source\":\"x\"}");

        String out = UserConfigImportMapper.toImportJson(body);

        JsonNode reparsed = MAPPER.readTree(out);
        assertThat(reparsed.has("user_options")).isTrue();
        assertThat(reparsed.has("user_configuration")).isFalse();
    }

    @Test
    void passesRawUserOptionsThrough() throws Exception {
        JsonNode body = parse("{\"user_options\":{\"rest_api\":{}}}");

        String out = UserConfigImportMapper.toImportJson(body);

        assertThat(MAPPER.readTree(out).has("user_options")).isTrue();
    }

    @Test
    void reportsImportedTopLevelSections() {
        JsonNode body = parse("{\"user_options\":{},\"display\":{}}");

        assertThat(UserConfigImportMapper.importedSections(body))
            .containsExactlyInAnyOrderElementsOf(List.of("user_options", "display"));
    }

    @Test
    void reportsSectionsFromInsideTheWrapper() {
        JsonNode body = parse("{\"user_configuration\":{\"user_options\":{}}}");

        assertThat(UserConfigImportMapper.importedSections(body))
            .containsExactly("user_options");
    }

    @Test
    void rejectsEmptyObject() {
        JsonNode body = parse("{}");
        assertThatThrownBy(() -> UserConfigImportMapper.toImportJson(body))
            .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void rejectsNonObjectPayloads() {
        assertThatThrownBy(() -> UserConfigImportMapper.toImportJson(parse("[]")))
            .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> UserConfigImportMapper.toImportJson(null))
            .isInstanceOf(IllegalArgumentException.class);
    }
}
