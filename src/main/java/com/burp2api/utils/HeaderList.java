package com.burp2api.utils;

import burp.api.montoya.http.message.HttpHeader;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

/**
 * Builds a structured {@code headers_list} — an ordered array of
 * {@code {"name", "value"}} entries — so clients can read individual headers
 * without re-parsing the flattened {@code headers} string. Order and duplicates
 * (e.g. multiple {@code Set-Cookie}) are preserved.
 *
 * <p>The live send/replay paths build the list straight from the Montoya
 * {@link HttpHeader} list, which is exact. The DB-backed responders only have
 * the stored header string, so {@link #fromStoredString(String)} parses that.
 *
 * <p>Two stored forms exist. Every capture path to date stores
 * {@code List<HttpHeader>.toString()} — {@code [Name: Value, Name: Value]},
 * bracket-wrapped and {@code ", "}-joined — which is ambiguous, because a
 * header value may legitimately contain {@code ", "}. Splitting such a blob
 * naively shreds comma-valued headers and drops the fragments that have no
 * colon, so that form is re-joined token-aware: a fragment opens a new header
 * only when the text before its first colon is a valid RFC 9110 field name.
 * That recovers real-world traffic but cannot be exact in principle
 * (see issue #20). The brackets are checked first: a captured value may itself
 * contain a raw newline, and only an unbracketed blob is a newline-separated
 * block to be parsed line by line.
 */
public final class HeaderList {

    /** RFC 9110 field name: one or more tchar. */
    private static final Pattern FIELD_NAME =
            Pattern.compile("[!#$%&'*+\\-.^_`|~0-9A-Za-z]+");

    private HeaderList() {
    }

    /** Exact structured list from a Montoya header list. */
    public static List<Map<String, String>> fromMontoya(List<? extends HttpHeader> headers) {
        List<Map<String, String>> out = new ArrayList<>();
        if (headers == null) {
            return out;
        }
        for (HttpHeader header : headers) {
            out.add(entry(header.name(), header.value()));
        }
        return out;
    }

    /**
     * Best-effort structured list from a stored header blob. A newline-separated
     * block is parsed exactly, one {@code Name: Value} per line. A legacy
     * {@code List.toString()} blob is un-bracketed and re-joined token-aware so
     * comma-containing values survive. Anything else is treated as a single
     * header line rather than comma-split, because only the bracketed form is
     * known to be a serialized list.
     */
    public static List<Map<String, String>> fromStoredString(String stored) {
        if (stored == null || stored.isBlank()) {
            return new ArrayList<>();
        }
        String trimmed = stored.strip();

        boolean legacyListBlob = trimmed.startsWith("[") && trimmed.endsWith("]");
        if (legacyListBlob) {
            trimmed = trimmed.substring(1, trimmed.length() - 1);
        }

        // Order matters. A bracketed blob is a serialized list whose *values* may
        // contain a raw newline — captured CRLF-injection payloads do exactly that.
        // Splitting those on the newline makes the first line parse as a single
        // header whose value swallows every header before the injection point, so
        // the bracket signal wins and the newline stays inside the value (#20).
        if (legacyListBlob) {
            return parseLines(rejoinCommaJoined(trimmed));
        }
        if (trimmed.contains("\n")) {
            return parseLines(List.of(trimmed.split("\\r?\\n")));
        }
        return parseLines(List.of(trimmed));
    }

    /**
     * Undoes a {@code ", "} join. A fragment continues the previous header
     * unless it opens a new one, so {@code Cache-Control: private, max-age=0}
     * survives whole and a colon inside a value
     * ({@code Expires: Fri, 24 Jul 2026 08:19:53 GMT}) does not fabricate a
     * header named {@code 24 Jul 2026 08}.
     */
    private static List<String> rejoinCommaJoined(String blob) {
        List<String> lines = new ArrayList<>();
        for (String fragment : blob.split(", ")) {
            if (lines.isEmpty() || opensHeader(fragment)) {
                lines.add(fragment);
            } else {
                lines.set(lines.size() - 1, lines.get(lines.size() - 1) + ", " + fragment);
            }
        }
        return lines;
    }

    private static boolean opensHeader(String fragment) {
        int idx = fragment.indexOf(':');
        return idx > 0 && FIELD_NAME.matcher(fragment.substring(0, idx).strip()).matches();
    }

    private static List<Map<String, String>> parseLines(List<String> lines) {
        List<Map<String, String>> out = new ArrayList<>();
        for (String raw : lines) {
            String line = raw.strip();
            int idx = line.indexOf(':');
            if (idx > 0) {
                String name = line.substring(0, idx).strip();
                String value = line.substring(idx + 1).strip();
                if (!name.isEmpty()) {
                    out.add(entry(name, value));
                }
            }
        }
        return out;
    }

    private static Map<String, String> entry(String name, String value) {
        Map<String, String> m = new LinkedHashMap<>();
        m.put("name", name);
        m.put("value", value == null ? "" : value);
        return m;
    }
}
