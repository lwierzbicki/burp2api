package com.burp2api.utils;

import static org.assertj.core.api.Assertions.assertThat;

import com.burp2api.utils.BodyCodec.EncodedBody;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import org.junit.jupiter.api.Test;

/**
 * Regression coverage for ticket #7: captured-content responses must be
 * RFC 8259-valid JSON. Every control character 0x00-0x1F must round-trip
 * through the response mapper without being emitted raw, and binary/non-UTF-8
 * bodies must survive as Base64 rather than corrupt the payload.
 */
class BodyCodecTest {

    private final ObjectMapper mapper = new ObjectMapper();

    @Test
    void everyControlCharRoundTripsThroughTheMapperAsValidJson() throws Exception {
        byte[] controls = new byte[0x20 + 16];
        for (int i = 0x00; i <= 0x1F; i++) {
            controls[i] = (byte) i;
        }
        byte[] tail = "<html></html>".getBytes(StandardCharsets.UTF_8);
        System.arraycopy(tail, 0, controls, 0x20, tail.length);
        String body = new String(controls, StandardCharsets.UTF_8);

        EncodedBody encoded = BodyCodec.encodeBytes(controls);
        assertThat(encoded.encoding()).isEqualTo(BodyCodec.UTF8);

        Map<String, Object> response = new HashMap<>();
        response.put("body", encoded.body());
        response.put("body_encoding", encoded.encoding());
        String json = mapper.writeValueAsString(response);

        // No raw control character may appear anywhere in the serialized JSON.
        for (int i = 0; i < json.length(); i++) {
            assertThat(json.charAt(i))
                .withFailMessage("raw control char 0x%02X at index %d", (int) json.charAt(i), i)
                .isGreaterThanOrEqualTo((char) 0x20);
        }

        // A plain client parses it back losslessly.
        @SuppressWarnings("unchecked")
        Map<String, Object> parsed = mapper.readValue(json, Map.class);
        assertThat(parsed.get("body")).isEqualTo(body);
        assertThat(parsed.get("body_encoding")).isEqualTo(BodyCodec.UTF8);
    }

    @Test
    void nulByteInBodyStaysValidJson() throws Exception {
        byte[] raw = new byte[] {'a', 0x00, 'b'};
        EncodedBody encoded = BodyCodec.encodeBytes(raw);
        assertThat(encoded.encoding()).isEqualTo(BodyCodec.UTF8);

        String json = mapper.writeValueAsString(Map.of("body", encoded.body()));
        assertThat(json).contains("\\u0000");

        @SuppressWarnings("unchecked")
        Map<String, Object> parsed = mapper.readValue(json, Map.class);
        assertThat(parsed.get("body")).isEqualTo(new String(raw, StandardCharsets.UTF_8));
    }

    @Test
    void binaryBodyIsBase64AndDecodesToOriginalBytes() {
        // Invalid UTF-8: lone continuation byte and a truncated multibyte lead.
        byte[] raw = new byte[] {(byte) 0xFF, (byte) 0xFE, 0x00, (byte) 0x80, (byte) 0xC3, 0x28};

        EncodedBody encoded = BodyCodec.encodeBytes(raw);

        assertThat(encoded.encoding()).isEqualTo(BodyCodec.BASE64);
        assertThat(Base64.getDecoder().decode(encoded.body())).isEqualTo(raw);
    }

    @Test
    void validUtf8MultibyteStaysText() {
        byte[] raw = "café — 日本語".getBytes(StandardCharsets.UTF_8);

        EncodedBody encoded = BodyCodec.encodeBytes(raw);

        assertThat(encoded.encoding()).isEqualTo(BodyCodec.UTF8);
        assertThat(encoded.body()).isEqualTo("café — 日本語");
    }

    @Test
    void storedLatin1StringRecoversOriginalBinaryBytes() {
        // Burp bodyToString() maps each raw byte to one ISO-8859-1 char; that is
        // how a binary body looks after a DB round-trip.
        byte[] raw = new byte[] {(byte) 0xFF, 0x00, (byte) 0x80, (byte) 0xC3, 0x28};
        String stored = new String(raw, StandardCharsets.ISO_8859_1);

        EncodedBody encoded = BodyCodec.encodeStoredString(stored);

        assertThat(encoded.encoding()).isEqualTo(BodyCodec.BASE64);
        assertThat(Base64.getDecoder().decode(encoded.body())).isEqualTo(raw);
    }

    @Test
    void storedAsciiTextStringStaysText() {
        byte[] raw = "tab\tand newline\nkept".getBytes(StandardCharsets.ISO_8859_1);
        String stored = new String(raw, StandardCharsets.ISO_8859_1);

        EncodedBody encoded = BodyCodec.encodeStoredString(stored);

        assertThat(encoded.encoding()).isEqualTo(BodyCodec.UTF8);
        assertThat(encoded.body()).isEqualTo("tab\tand newline\nkept");
    }

    @Test
    void nullAndEmptyBodiesEncodeAsEmptyUtf8() {
        assertThat(BodyCodec.encodeBytes(null).body()).isEmpty();
        assertThat(BodyCodec.encodeBytes(null).encoding()).isEqualTo(BodyCodec.UTF8);
        assertThat(BodyCodec.encodeStoredString(null).body()).isEmpty();
        assertThat(BodyCodec.encodeStoredString("").encoding()).isEqualTo(BodyCodec.UTF8);
    }
}
