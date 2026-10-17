package com.burp2api.utils;

import burp.api.montoya.http.message.requests.HttpRequest;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * Parses caller-supplied request headers from the flexible shapes accepted by
 * the request-sending endpoints ({@code /proxy/send}, {@code /scanner/scan-request})
 * and applies them to a Montoya {@link HttpRequest}.
 *
 * <p>Three input shapes are accepted:
 * <ul>
 *   <li><b>JSON object</b> {@code {"Name": "Value", ...}} — insertion order is
 *       preserved; a JSON object cannot carry a duplicate name.</li>
 *   <li><b>JSON array of pairs</b> {@code [["Name","Value"], ...]} — the escape
 *       hatch for controlling order or repeating a name.</li>
 *   <li><b>Legacy CRLF string</b> {@code "Name: Value\r\nName2: Value2"} — split
 *       on line breaks, then on the first colon.</li>
 * </ul>
 *
 * <p>Headers are applied last-wins per name: a repeated name updates the prior
 * value rather than emitting a second header line, matching how the send path
 * has always overridden auto-generated headers such as {@code Host}.
 */
public final class HeaderInput {

    private HeaderInput() {
    }

    /** A single parsed request header. */
    public record Header(String name, String value) {
    }

    /**
     * Parses the raw {@code headers} value into an ordered list. A null, blank,
     * or otherwise empty input yields an empty list (no headers applied).
     */
    public static List<Header> parse(Object raw) {
        List<Header> out = new ArrayList<>();
        if (raw == null) {
            return out;
        }
        if (raw instanceof Map<?, ?> map) {
            for (Map.Entry<?, ?> entry : map.entrySet()) {
                addHeader(out, entry.getKey(), entry.getValue());
            }
        } else if (raw instanceof List<?> list) {
            for (Object item : list) {
                if (item instanceof List<?> pair && pair.size() >= 2) {
                    addHeader(out, pair.get(0), pair.get(1));
                }
            }
        } else {
            for (String line : String.valueOf(raw).split("\\r?\\n")) {
                int idx = line.indexOf(':');
                if (idx > 0) {
                    addHeader(out, line.substring(0, idx), line.substring(idx + 1).trim());
                }
            }
        }
        return out;
    }

    /** Applies parsed headers to a request, last-wins per header name. */
    public static HttpRequest applyTo(HttpRequest request, List<Header> headers) {
        for (Header h : headers) {
            request = request.hasHeader(h.name())
                ? request.withUpdatedHeader(h.name(), h.value())
                : request.withAddedHeader(h.name(), h.value());
        }
        return request;
    }

    /**
     * Serializes parsed headers to a CRLF {@code "Name: Value"} block, the
     * canonical form stored with captured traffic.
     */
    public static String toBlock(List<Header> headers) {
        StringBuilder sb = new StringBuilder();
        for (Header h : headers) {
            if (sb.length() > 0) {
                sb.append("\r\n");
            }
            sb.append(h.name()).append(": ").append(h.value());
        }
        return sb.toString();
    }

    private static void addHeader(List<Header> out, Object name, Object value) {
        String n = String.valueOf(name).trim();
        if (!n.isEmpty()) {
            out.add(new Header(n, value == null ? "" : String.valueOf(value)));
        }
    }
}
