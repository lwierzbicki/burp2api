package com.burp2api.utils;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Prepares values for the SQLite store, distinguishing short scalar columns
 * from captured content.
 *
 * <p>{@link #scalar(String, int)} keeps the historic hygiene — strip control
 * characters, truncate with an ellipsis — which is harmless on a method, URL,
 * host, session tag, or HTTP version.
 *
 * <p>{@link #content(String, int)} is for headers and bodies, which are
 * evidence. It never removes a character. Burp's {@code bodyToString()} maps
 * one raw byte to one ISO-8859-1 char, so stripping control characters there
 * deletes bytes outright and no reader can recover them; the pre-#20 sanitizer
 * did exactly that, and above its cap wrote {@code "..."} into the body itself,
 * making the corruption indistinguishable from captured content. JSON safety is
 * handled downstream by {@link BodyCodec}, not here.
 *
 * <p>The full 0x00–0xFF range round-trips a SQLite TEXT column exactly through
 * the pinned JDBC driver. The one caveat is that SQLite's own SQL string
 * functions stop at an embedded NUL, so {@code LIKE}/{@code length()} over a
 * body containing one see only the prefix.
 */
public final class StoredText {

    private static final Logger logger = LoggerFactory.getLogger(StoredText.class);

    private StoredText() {
    }

    /**
     * Sanitizes a short scalar column: control characters removed, truncated to
     * {@code maxLength} with a trailing ellipsis.
     */
    public static String scalar(String input, int maxLength) {
        if (input == null) {
            return "";
        }

        String sanitized = input.replaceAll("[\u0000-\u0008\u000B-\u000C\u000E-\u001F\u007F]", "");

        if (sanitized.length() > maxLength) {
            sanitized = sanitized.substring(0, maxLength - 3) + "...";
            logger.debug("Truncated scalar from {} to {} characters", input.length(), sanitized.length());
        }

        return sanitized;
    }

    /**
     * Prepares captured content for storage verbatim. Characters are never
     * removed. A value longer than {@code maxLength} is cut to exactly that
     * length — no marker is written into the data — and the trim is logged so
     * it is never silent.
     */
    public static String content(String input, int maxLength) {
        if (input == null) {
            return "";
        }

        if (input.length() > maxLength) {
            logger.warn("Captured content exceeds the storage cap and was trimmed: {} -> {} characters. "
                + "Raise BURP2API_MAX_STORED_CONTENT_CHARS to keep the whole value.",
                input.length(), maxLength);
            return input.substring(0, maxLength);
        }

        return input;
    }

    /**
     * Whether a stored value reached the storage cap and may therefore be a
     * capped prefix rather than the whole captured content. {@link #content}
     * trims only a value that <em>exceeds</em> the cap, so a stored length equal
     * to the cap is the one length indistinguishable from a complete body of
     * exactly that size; it is reported capped, conservatively. Evidence
     * consumers must be able to tell a possibly-trimmed body from a complete one
     * (#20, #23), and the store never marks the trim inline.
     */
    public static boolean isCapped(String stored, int maxLength) {
        return stored != null && stored.length() >= maxLength;
    }
}
