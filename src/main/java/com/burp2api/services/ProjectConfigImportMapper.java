package com.burp2api.services;

import com.fasterxml.jackson.databind.JsonNode;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

/**
 * Pure helpers for the project-options import endpoint (ticket #13, Phase 3):
 * normalize an incoming body into the JSON string that Burp's
 * {@code BurpSuite.importProjectOptionsFromJson(String)} expects, and list the
 * top-level sections being imported. This is the Montoya-path throttle lever —
 * it lets a resource-pool template (concurrency + throttle) be applied via the
 * API without the built-in REST service. No Burp, no I/O.
 *
 * <p>Accepts either a raw project-options object (the shape Burp exports, e.g.
 * {@code {"project_options": {...}}}) or the export-shaped wrapper this tool's
 * {@code GET /scope/project-config} returns
 * ({@code {"project_configuration": {...}}}), so an exported config round-trips.
 */
public final class ProjectConfigImportMapper {

    private static final String WRAPPER_KEY = "project_configuration";

    private ProjectConfigImportMapper() {
    }

    /**
     * Resolve the object Burp should import: the {@code project_configuration}
     * wrapper's contents when present, otherwise the body itself.
     *
     * @throws IllegalArgumentException if the payload is null, not a JSON object,
     *     or empty.
     */
    private static JsonNode resolveOptions(JsonNode body) {
        if (body == null || !body.isObject()) {
            throw new IllegalArgumentException(
                "project config import requires a JSON object body");
        }
        JsonNode options = body;
        JsonNode wrapped = body.get(WRAPPER_KEY);
        if (wrapped != null && wrapped.isObject()) {
            options = wrapped;
        }
        if (options.size() == 0) {
            throw new IllegalArgumentException(
                "project config import body has no options to apply");
        }
        return options;
    }

    /** Serialize the resolved options object into the import JSON string. */
    public static String toImportJson(JsonNode body) {
        return resolveOptions(body).toString();
    }

    /** Top-level section names that will be imported (e.g. {@code project_options}). */
    public static List<String> importedSections(JsonNode body) {
        List<String> sections = new ArrayList<>();
        Iterator<String> names = resolveOptions(body).fieldNames();
        while (names.hasNext()) {
            sections.add(names.next());
        }
        return sections;
    }
}
