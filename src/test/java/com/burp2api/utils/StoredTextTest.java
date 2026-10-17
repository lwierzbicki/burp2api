package com.burp2api.utils;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;

/**
 * Ticket #20: captured content is evidence and must be stored verbatim. The
 * pre-#20 sanitizer deleted control characters from every column, which for a
 * body — one latin-1 char per raw byte, via Burp's {@code bodyToString()} —
 * silently removed bytes, and above its cap wrote {@code "..."} into the body
 * itself. Short scalar columns keep the old hygiene; content does not.
 */
class StoredTextTest {

    /** All 256 byte values as latin-1 chars, exactly what bodyToString() yields. */
    private String allByteValues() {
        StringBuilder sb = new StringBuilder(256);
        for (int i = 0; i < 256; i++) {
            sb.append((char) i);
        }
        return sb.toString();
    }

    @Test
    void contentPreservesEveryByteValueIncludingControlCharacters() {
        String raw = allByteValues();

        String stored = StoredText.content(raw, 65536);

        assertThat(stored).hasSize(256).isEqualTo(raw);
    }

    @Test
    void contentTruncatesAtTheCapWithoutWritingAMarkerIntoTheData() {
        String raw = "A".repeat(100);

        String stored = StoredText.content(raw, 10);

        assertThat(stored).isEqualTo("AAAAAAAAAA");
        assertThat(stored).doesNotContain("...");
    }

    @Test
    void contentLeavesAValueAtExactlyTheCapAlone() {
        assertThat(StoredText.content("ABCDE", 5)).isEqualTo("ABCDE");
    }

    @Test
    void scalarStripsControlCharactersAndTruncatesWithAMarker() {
        assertThat(StoredText.scalar("GE\u0001T", 10)).isEqualTo("GET");
        assertThat(StoredText.scalar("A".repeat(20), 10)).isEqualTo("AAAAAAA...");
    }

    @Test
    void scalarAndContentTreatNullAsEmpty() {
        assertThat(StoredText.scalar(null, 10)).isEmpty();
        assertThat(StoredText.content(null, 10)).isEmpty();
    }

    @Test
    void isCappedReportsAStoredValueThatReachedTheCap() {
        // content() trims only what exceeds the cap, so a stored length equal to
        // the cap is the boundary that cannot be told apart from a complete body
        // of exactly that size -- reported capped, conservatively (#23).
        assertThat(StoredText.isCapped(StoredText.content("A".repeat(100), 10), 10)).isTrue();
        assertThat(StoredText.isCapped("A".repeat(10), 10)).isTrue();
    }

    @Test
    void isCappedReportsAValueBelowTheCapAsComplete() {
        assertThat(StoredText.isCapped("ABCDE", 10)).isFalse();
        assertThat(StoredText.isCapped("", 10)).isFalse();
        assertThat(StoredText.isCapped(null, 10)).isFalse();
    }
}
