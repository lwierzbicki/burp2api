package com.burp2api.services;

import com.fasterxml.jackson.databind.JsonNode;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

/**
 * Pure helpers for the user-options import endpoint (ticket #14): normalize an
 * incoming body into the JSON string that Burp's
 * {@code BurpSuite.importUserOptionsFromJson(String)} expects, and list the
 * top-level sections being imported. User options are where the built-in REST
 * API service settings live (Settings &rarr; Suite &rarr; REST API), so this is
 * the lever for capturing/applying the keyless {@code rest_api} block over the
 * API instead of the UI. No Burp, no I/O.
 *
 * <p>Accepts either a raw user-options object (the shape Burp exports, e.g.
 * {@code {"user_options": {...}}}) or the export-shaped wrapper this tool's
 * {@code GET /config/user-config} returns ({@code {"user_configuration": {...}}}),
 * so an exported config round-trips. Mirrors {@link ProjectConfigImportMapper}.
 */
public final class UserConfigImportMapper {

    private static final String WRAPPER_KEY = "user_configuration";

    private UserConfigImportMapper() {
    }

    /**
     * Resolve the object Burp should import: the {@code user_configuration}
     * wrapper's contents when present, otherwise the body itself.
     *
     * @throws IllegalArgumentException if the payload is null, not a JSON object,
     *     or empty.
     */
    private static JsonNode resolveOptions(JsonNode body) {
        if (body == null || !body.isObject()) {
            throw new IllegalArgumentException(
                "user config import requires a JSON object body");
        }
        JsonNode options = body;
        JsonNode wrapped = body.get(WRAPPER_KEY);
        if (wrapped != null && wrapped.isObject()) {
            options = wrapped;
        }
        if (options.size() == 0) {
            throw new IllegalArgumentException(
                "user config import body has no options to apply");
        }
        return options;
    }

    /** Serialize the resolved options object into the import JSON string. */
    public static String toImportJson(JsonNode body) {
        return resolveOptions(body).toString();
    }

    /** Top-level section names that will be imported (e.g. {@code user_options}). */
    public static List<String> importedSections(JsonNode body) {
        List<String> sections = new ArrayList<>();
        Iterator<String> names = resolveOptions(body).fieldNames();
        while (names.hasNext()) {
            sections.add(names.next());
        }
        return sections;
    }
}
