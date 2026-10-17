package com.burp2api.services;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.JsonNode;
import java.util.List;
import org.junit.jupiter.api.Test;

/**
 * Ticket #13 (Phase 3): pure mapping for the project-options import endpoint —
 * unwrap the export-shaped wrapper, validate the payload is a non-empty JSON
 * object, and surface the imported top-level sections. No Burp, no I/O.
 */
class ProjectConfigImportMapperTest {

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
        // GET /scope/project-config returns {"project_configuration": {...}, ...};
        // a round-tripped POST of that must import the inner object only.
        JsonNode body = parse("{\"project_configuration\":{\"project_options\":"
            + "{\"resource_pool\":{\"pools\":[]}}},\"source\":\"x\"}");

        String out = ProjectConfigImportMapper.toImportJson(body);

        JsonNode reparsed = MAPPER.readTree(out);
        assertThat(reparsed.has("project_options")).isTrue();
        assertThat(reparsed.has("project_configuration")).isFalse();
    }

    @Test
    void passesRawProjectOptionsThrough() throws Exception {
        JsonNode body = parse("{\"project_options\":{\"connections\":{}}}");

        String out = ProjectConfigImportMapper.toImportJson(body);

        assertThat(MAPPER.readTree(out).has("project_options")).isTrue();
    }

    @Test
    void reportsImportedTopLevelSections() {
        JsonNode body = parse("{\"project_options\":{},\"target\":{}}");

        assertThat(ProjectConfigImportMapper.importedSections(body))
            .containsExactlyInAnyOrderElementsOf(List.of("project_options", "target"));
    }

    @Test
    void reportsSectionsFromInsideTheWrapper() {
        JsonNode body = parse("{\"project_configuration\":{\"project_options\":{}}}");

        assertThat(ProjectConfigImportMapper.importedSections(body))
            .containsExactly("project_options");
    }

    @Test
    void rejectsEmptyObject() {
        JsonNode body = parse("{}");
        assertThatThrownBy(() -> ProjectConfigImportMapper.toImportJson(body))
            .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void rejectsNonObjectPayloads() {
        assertThatThrownBy(() -> ProjectConfigImportMapper.toImportJson(parse("[]")))
            .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> ProjectConfigImportMapper.toImportJson(null))
            .isInstanceOf(IllegalArgumentException.class);
    }
}
