package com.burp2api.utils;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Reconstructs the live session cookies for a host from captured proxy traffic.
 *
 * <p>The Burp Montoya {@code CookieJar} API can set cookies but cannot enumerate
 * the cookies the browser already holds. The freshest reliable snapshot of a
 * live authenticated session is therefore the {@code Cookie} request header on
 * the most recent proxied request to that host, enriched with attributes from
 * {@code Set-Cookie} response headers. This class derives that snapshot from
 * header blocks so it can be unit tested without Burp or a database.
 *
 * @version 1.0.0
 */
public final class CookieReconstructor {

    private CookieReconstructor() {
    }

    /** Header blocks for one captured request/response exchange. */
    public record Exchange(String requestHeaders, String responseHeaders) {
    }

    /** A single reconstructed cookie and where its value was observed. */
    public record Cookie(String name, String value, String domain, String path,
                         boolean secure, boolean httpOnly, String source) {
    }

    /** Reconstructed cookies plus a ready-to-use {@code Cookie} header value. */
    public record Result(List<Cookie> cookies, String cookieHeader) {
    }

    /**
     * Reconstructs the current cookies for {@code host} from a list of exchanges
     * ordered newest first. For each cookie name the most recently observed
     * value wins; request {@code Cookie} headers take precedence over
     * {@code Set-Cookie} values within the same exchange because they reflect
     * what the client actually holds.
     */
    public static Result reconstruct(String host, List<Exchange> exchangesNewestFirst) {
        String defaultDomain = host == null ? "" : host;

        // Attributes from Set-Cookie, newest-first wins.
        Map<String, SetCookieAttrs> attributes = new LinkedHashMap<>();
        // Current value per cookie, newest-first wins (insertion order preserved).
        Map<String, ValueSource> values = new LinkedHashMap<>();

        if (exchangesNewestFirst != null) {
            for (Exchange exchange : exchangesNewestFirst) {
                List<SetCookieAttrs> setCookies = parseSetCookieHeaders(
                        exchange == null ? null : exchange.responseHeaders());
                for (SetCookieAttrs attrs : setCookies) {
                    attributes.putIfAbsent(attrs.name, attrs);
                }

                // Request Cookie header is the freshest view of the live jar.
                Map<String, String> requestCookies = parseRequestCookieHeader(
                        exchange == null ? null : exchange.requestHeaders());
                for (Map.Entry<String, String> entry : requestCookies.entrySet()) {
                    values.putIfAbsent(entry.getKey(),
                            new ValueSource(entry.getValue(), "request"));
                }

                // Fall back to Set-Cookie values for cookies never echoed back.
                for (SetCookieAttrs attrs : setCookies) {
                    if (attrs.deleted) {
                        continue;
                    }
                    values.putIfAbsent(attrs.name,
                            new ValueSource(attrs.value, "response"));
                }
            }
        }

        List<Cookie> cookies = new ArrayList<>();
        StringBuilder header = new StringBuilder();
        for (Map.Entry<String, ValueSource> entry : values.entrySet()) {
            String name = entry.getKey();
            ValueSource source = entry.getValue();
            SetCookieAttrs attrs = attributes.get(name);
            String domain = attrs != null && !attrs.domain.isEmpty() ? attrs.domain : defaultDomain;
            String path = attrs != null && !attrs.path.isEmpty() ? attrs.path : "/";
            boolean secure = attrs != null && attrs.secure;
            boolean httpOnly = attrs != null && attrs.httpOnly;

            cookies.add(new Cookie(name, source.value, domain, path, secure, httpOnly, source.source));

            if (header.length() > 0) {
                header.append("; ");
            }
            header.append(name).append('=').append(source.value);
        }

        return new Result(cookies, header.toString());
    }

    /**
     * Parses the {@code Cookie} request header from a header block into an
     * ordered name/value map. Returns an empty map when no header is present.
     */
    public static Map<String, String> parseRequestCookieHeader(String requestHeaders) {
        Map<String, String> cookies = new LinkedHashMap<>();
        if (requestHeaders == null) {
            return cookies;
        }
        for (String line : splitHeaderBlock(requestHeaders)) {
            int colon = line.indexOf(':');
            if (colon < 0) {
                continue;
            }
            if (!"cookie".equalsIgnoreCase(line.substring(0, colon).trim())) {
                continue;
            }
            String value = line.substring(colon + 1).trim();
            for (String pair : value.split(";")) {
                String trimmed = pair.trim();
                if (trimmed.isEmpty()) {
                    continue;
                }
                int eq = trimmed.indexOf('=');
                if (eq <= 0) {
                    continue;
                }
                String name = trimmed.substring(0, eq).trim();
                String cookieValue = trimmed.substring(eq + 1).trim();
                if (!name.isEmpty()) {
                    cookies.put(name, cookieValue);
                }
            }
        }
        return cookies;
    }

    /**
     * Parses all {@code Set-Cookie} response headers from a header block,
     * preserving order, including attributes and deletion markers.
     */
    public static List<SetCookieAttrs> parseSetCookieHeaders(String responseHeaders) {
        List<SetCookieAttrs> result = new ArrayList<>();
        if (responseHeaders == null) {
            return result;
        }
        for (String line : splitHeaderBlock(responseHeaders)) {
            int colon = line.indexOf(':');
            if (colon < 0) {
                continue;
            }
            if (!"set-cookie".equalsIgnoreCase(line.substring(0, colon).trim())) {
                continue;
            }
            String value = line.substring(colon + 1).trim();
            String[] parts = value.split(";");
            if (parts.length == 0) {
                continue;
            }
            String nameValue = parts[0].trim();
            int eq = nameValue.indexOf('=');
            if (eq <= 0) {
                continue;
            }
            String name = nameValue.substring(0, eq).trim();
            String cookieValue = nameValue.substring(eq + 1).trim();
            if (name.isEmpty()) {
                continue;
            }

            String domain = "";
            String path = "";
            boolean secure = false;
            boolean httpOnly = false;
            boolean deleted = cookieValue.isEmpty();
            for (int i = 1; i < parts.length; i++) {
                String attr = parts[i].trim();
                String lower = attr.toLowerCase();
                if (lower.startsWith("domain=")) {
                    domain = stripLeadingDot(attr.substring(7).trim());
                } else if (lower.startsWith("path=")) {
                    path = attr.substring(5).trim();
                } else if (lower.equals("secure")) {
                    secure = true;
                } else if (lower.equals("httponly")) {
                    httpOnly = true;
                } else if (lower.startsWith("max-age=")) {
                    if ("0".equals(attr.substring(8).trim())) {
                        deleted = true;
                    }
                }
            }
            result.add(new SetCookieAttrs(name, cookieValue, domain, path, secure, httpOnly, deleted));
        }
        return result;
    }

    /**
     * Splits a header block into individual {@code Name: value} entries.
     *
     * <p>Supports two formats: a real HTTP header block with one header per
     * line (CRLF or LF), and the single-line {@code List.toString()} form used
     * by the captured-traffic store, e.g.
     * {@code "[Host: h, Cookie: a=b; c=d, Accept: x]"}. In the bracketed form,
     * entries are separated by {@code ", "}; a value that itself contains
     * {@code ", "} (e.g. an {@code Accept} list, or a {@code Set-Cookie}
     * {@code Expires} date) may fragment into colon-less pieces, which the
     * callers skip. The request {@code Cookie} header uses {@code "; "}
     * internally, so it is recovered intact.
     */
    static String[] splitHeaderBlock(String block) {
        if (block == null) {
            return new String[0];
        }
        String trimmed = block.trim();
        if (trimmed.length() >= 2
                && trimmed.startsWith("[") && trimmed.endsWith("]")
                && trimmed.indexOf('\n') < 0) {
            String inner = trimmed.substring(1, trimmed.length() - 1);
            if (inner.isBlank()) {
                return new String[0];
            }
            return inner.split(", ");
        }
        return block.split("\r?\n");
    }

    private static String stripLeadingDot(String domain) {
        return domain.startsWith(".") ? domain.substring(1) : domain;
    }

    /** Parsed attributes of a single {@code Set-Cookie} header. */
    public static final class SetCookieAttrs {
        public final String name;
        public final String value;
        public final String domain;
        public final String path;
        public final boolean secure;
        public final boolean httpOnly;
        public final boolean deleted;

        SetCookieAttrs(String name, String value, String domain, String path,
                       boolean secure, boolean httpOnly, boolean deleted) {
            this.name = name;
            this.value = value;
            this.domain = domain;
            this.path = path;
            this.secure = secure;
            this.httpOnly = httpOnly;
            this.deleted = deleted;
        }
    }

    private static final class ValueSource {
        final String value;
        final String source;

        ValueSource(String value, String source) {
            this.value = value;
            this.source = source;
        }
    }
}
