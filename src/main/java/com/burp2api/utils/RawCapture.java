package com.burp2api.utils;

/**
 * Applies the raw-capture size policy (#24) to a byte-exact request or response
 * message before it is written to the {@code request_raw} / {@code response_raw}
 * BLOB columns.
 *
 * <p>Three outcomes, kept distinct so a reader can tell them apart:
 * <ul>
 *   <li><b>absent</b> — no bytes were offered ({@code raw == null}); the row was
 *       captured before raw storage existed or through a path that only has a
 *       reconstructed string. {@code present() == false}, {@code omitted == false}.</li>
 *   <li><b>stored</b> — bytes at or below the cap; kept verbatim.
 *       {@code present() == true}.</li>
 *   <li><b>omitted</b> — bytes over the cap; dropped and flagged rather than
 *       truncated, because a partial raw message is worse than none for
 *       evidence. {@code present() == false}, {@code omitted == true}.</li>
 * </ul>
 *
 * <p>The cap is {@link com.burp2api.config.ApiConfig#getMaxRawBytes()}.
 */
public final class RawCapture {

    private final byte[] bytes;
    private final boolean omitted;

    private RawCapture(byte[] bytes, boolean omitted) {
        this.bytes = bytes;
        this.omitted = omitted;
    }

    /**
     * Applies the cap. {@code null} in means absent; a length over {@code maxBytes}
     * means omitted; otherwise the bytes are stored verbatim.
     */
    public static RawCapture cap(byte[] raw, int maxBytes) {
        if (raw == null) {
            return new RawCapture(null, false);
        }
        if (raw.length > maxBytes) {
            return new RawCapture(null, true);
        }
        return new RawCapture(raw, false);
    }

    /** The bytes to store, or {@code null} when absent or omitted. */
    public byte[] bytes() {
        return bytes;
    }

    /** True when a capture was offered but exceeded the cap. */
    public boolean omitted() {
        return omitted;
    }

    /** True when byte-exact content is available to store. */
    public boolean present() {
        return bytes != null;
    }
}
