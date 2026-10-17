package com.burp2api.utils;

import static org.assertj.core.api.Assertions.assertThat;

import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.Test;

class RawCaptureTest {

    @Test
    void nullBytesAreAbsentNotOmitted() {
        RawCapture c = RawCapture.cap(null, 100);
        assertThat(c.present()).isFalse();
        assertThat(c.omitted()).isFalse();
        assertThat(c.bytes()).isNull();
    }

    @Test
    void bytesAtOrBelowCapAreStoredVerbatim() {
        byte[] raw = "GET / HTTP/1.1\r\nHost: x\r\n\r\n".getBytes(StandardCharsets.ISO_8859_1);
        RawCapture c = RawCapture.cap(raw, raw.length);
        assertThat(c.present()).isTrue();
        assertThat(c.omitted()).isFalse();
        assertThat(c.bytes()).isEqualTo(raw);
    }

    @Test
    void bytesOverCapAreOmittedNotTruncated() {
        byte[] raw = new byte[101];
        RawCapture c = RawCapture.cap(raw, 100);
        assertThat(c.present()).isFalse();
        assertThat(c.omitted()).isTrue();
        assertThat(c.bytes()).isNull();
    }

    @Test
    void emptyBytesArePresent() {
        RawCapture c = RawCapture.cap(new byte[0], 100);
        assertThat(c.present()).isTrue();
        assertThat(c.omitted()).isFalse();
        assertThat(c.bytes()).isEmpty();
    }
}
