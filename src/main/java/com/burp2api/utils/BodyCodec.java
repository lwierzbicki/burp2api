package com.burp2api.utils;

import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CharsetDecoder;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Map;

/**
 * Encodes captured HTTP body content for safe, lossless inclusion in JSON
 * responses.
 *
 * <p>A body that is valid UTF-8 (including one that contains control characters
 * such as newlines, tabs, or NUL) is returned as a text string; the JSON
 * serializer escapes any control characters, so the payload stays RFC 8259
 * valid. A body that is not valid UTF-8 (binary or a foreign charset) would be
 * corrupted by a lossy decode, so it is returned Base64-encoded instead. Every
 * result carries an explicit {@code encoding} discriminator ({@code "utf-8"} or
 * {@code "base64"}) so a client can tell the two apart.
 */
public final class BodyCodec {

    public static final String UTF8 = "utf-8";
    public static final String BASE64 = "base64";

    private BodyCodec() {
    }

    /** An encoded body plus the discriminator describing how it was encoded. */
    public record EncodedBody(String body, String encoding) {
        public boolean isBase64() {
            return BASE64.equals(encoding);
        }
    }

    /**
     * Encodes raw body bytes. Valid UTF-8 stays text; anything else is Base64.
     */
    public static EncodedBody encodeBytes(byte[] raw) {
        byte[] bytes = raw != null ? raw : new byte[0];
        String text = strictUtf8(bytes);
        if (text != null) {
            return new EncodedBody(text, UTF8);
        }
        return new EncodedBody(Base64.getEncoder().encodeToString(bytes), BASE64);
    }

    /**
     * Encodes a body that was previously stored as a String. Burp's
     * {@code bodyToString()} maps each raw byte to one ISO-8859-1 character, and
     * that mapping round-trips losslessly through the SQLite TEXT store, so a
     * stored string whose characters are all {@code <= 0xFF} is converted back to
     * its original bytes before re-encoding. A stored string that already holds
     * real Unicode above U+00FF is treated as UTF-8 text as-is.
     */
    public static EncodedBody encodeStoredString(String stored) {
        if (stored == null || stored.isEmpty()) {
            return new EncodedBody("", UTF8);
        }
        byte[] raw = latin1Bytes(stored);
        if (raw != null) {
            return encodeBytes(raw);
        }
        return new EncodedBody(stored, UTF8);
    }

    /**
     * Writes an encoded body and its discriminator into a mutable response map,
     * replacing {@code bodyKey} with the encoded form.
     */
    public static void putEncoded(Map<String, Object> target, String bodyKey,
            String encodingKey, EncodedBody encoded) {
        target.put(bodyKey, encoded.body());
        target.put(encodingKey, encoded.encoding());
    }

    private static byte[] latin1Bytes(String s) {
        byte[] out = new byte[s.length()];
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c > 0xFF) {
                return null;
            }
            out[i] = (byte) c;
        }
        return out;
    }

    private static String strictUtf8(byte[] raw) {
        CharsetDecoder decoder = StandardCharsets.UTF_8.newDecoder()
                .onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT);
        try {
            return decoder.decode(ByteBuffer.wrap(raw)).toString();
        } catch (CharacterCodingException e) {
            return null;
        }
    }
}
