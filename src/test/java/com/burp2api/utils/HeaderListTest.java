package com.burp2api.utils;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import burp.api.montoya.http.message.HttpHeader;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

/**
 * Ticket #9: responses expose a structured {@code headers_list} alongside the
 * flattened {@code headers} string. Order and duplicates must be preserved, and
 * comma-containing values must not be split.
 */
class HeaderListTest {

    private HttpHeader header(String name, String value) {
        HttpHeader h = mock(HttpHeader.class);
        when(h.name()).thenReturn(name);
        when(h.value()).thenReturn(value);
        return h;
    }

    @Test
    void fromMontoyaPreservesOrderDuplicatesAndCommaValues() {
        List<HttpHeader> headers = List.of(
            header("Server", "nginx"),
            header("Date", "Mon, 06 Jul 2026 12:00:00 GMT"),
            header("Set-Cookie", "a=1; Path=/"),
            header("Set-Cookie", "b=2; Path=/"));

        List<Map<String, String>> list = HeaderList.fromMontoya(headers);

        assertThat(list).containsExactly(
            Map.of("name", "Server", "value", "nginx"),
            Map.of("name", "Date", "value", "Mon, 06 Jul 2026 12:00:00 GMT"),
            Map.of("name", "Set-Cookie", "value", "a=1; Path=/"),
            Map.of("name", "Set-Cookie", "value", "b=2; Path=/"));
    }

    @Test
    void fromMontoyaHandlesNullAndEmpty() {
        assertThat(HeaderList.fromMontoya(null)).isEmpty();
        assertThat(HeaderList.fromMontoya(List.of())).isEmpty();
    }

    @Test
    void fromStoredStringParsesNewlineFormExactlyIncludingCommaValues() {
        String stored = "Server: nginx\r\n"
            + "Date: Mon, 06 Jul 2026 12:00:00 GMT\n"
            + "Set-Cookie: a=1; Path=/\n"
            + "Set-Cookie: b=2; Path=/";

        List<Map<String, String>> list = HeaderList.fromStoredString(stored);

        assertThat(list).containsExactly(
            Map.of("name", "Server", "value", "nginx"),
            Map.of("name", "Date", "value", "Mon, 06 Jul 2026 12:00:00 GMT"),
            Map.of("name", "Set-Cookie", "value", "a=1; Path=/"),
            Map.of("name", "Set-Cookie", "value", "b=2; Path=/"));
    }

    @Test
    void fromStoredStringStripsBracketsAndFallsBackToCommaForSingleLine() {
        List<Map<String, String>> list =
            HeaderList.fromStoredString("[Server: nginx, X-Cache: HIT]");

        assertThat(list).containsExactly(
            Map.of("name", "Server", "value", "nginx"),
            Map.of("name", "X-Cache", "value", "HIT"));
    }

    /**
     * Ticket #20: no writer has ever produced the newline form — every capture
     * path stores {@code List<HttpHeader>.toString()}, so real rows look like
     * {@code [Name: Value, Name: Value]}. Splitting that on {@code ", "} shreds
     * comma-valued headers and silently drops the fragments that have no colon.
     */
    @Test
    void fromStoredStringRejoinsCommaValuesInALegacyListBlob() {
        String stored = "[Expires: Fri, 24 Jul 2026 08:19:53 GMT, "
            + "Cache-Control: private, max-age=0]";

        List<Map<String, String>> list = HeaderList.fromStoredString(stored);

        assertThat(list).containsExactly(
            Map.of("name", "Expires", "value", "Fri, 24 Jul 2026 08:19:53 GMT"),
            Map.of("name", "Cache-Control", "value", "private, max-age=0"));
    }

    /**
     * A continuation fragment may itself contain a colon. {@code 24 Jul 2026 08}
     * is not a valid RFC 9110 field name, so it must not open a new header.
     */
    @Test
    void fromStoredStringDoesNotSplitOnAColonInsideAContinuation() {
        String stored = "[Set-Cookie: a=1; Expires=Fri, 24 Jul 2026 08:19:53 GMT, "
            + "Set-Cookie: b=2]";

        List<Map<String, String>> list = HeaderList.fromStoredString(stored);

        assertThat(list).containsExactly(
            Map.of("name", "Set-Cookie", "value", "a=1; Expires=Fri, 24 Jul 2026 08:19:53 GMT"),
            Map.of("name", "Set-Cookie", "value", "b=2"));
    }

    /**
     * Ticket #20, found in live acceptance: a captured CRLF-injection payload puts
     * a raw newline <em>inside a value</em> of a legacy list blob. Treating that
     * newline as a header separator makes the first line parse as one header named
     * {@code Host} whose value swallows every real header — and curl export then
     * drops the lot, because it skips {@code Host}. The bracketed form is the
     * stronger signal, so it must be honoured before any newline split.
     */
    @Test
    void fromStoredStringKeepsHeadersWhenALegacyBlobValueContainsAnInjectedNewline() {
        String stored = "[Host: example.test, Cache-Control: max-age=0, "
            + "X-Inject: probe\nTransfer-Encoding: chunked, Content-Length: 31]";

        List<Map<String, String>> list = HeaderList.fromStoredString(stored);

        assertThat(list).containsExactly(
            Map.of("name", "Host", "value", "example.test"),
            Map.of("name", "Cache-Control", "value", "max-age=0"),
            Map.of("name", "X-Inject", "value", "probe\nTransfer-Encoding: chunked"),
            Map.of("name", "Content-Length", "value", "31"));
    }

    /** A single line with no brackets is one header, not a list to split. */
    @Test
    void fromStoredStringKeepsAnUnbracketedSingleLineIntact() {
        List<Map<String, String>> list =
            HeaderList.fromStoredString("Content-Type: text/plain, charset=utf-8");

        assertThat(list).containsExactly(
            Map.of("name", "Content-Type", "value", "text/plain, charset=utf-8"));
    }

    @Test
    void fromStoredStringHandlesNullBlankAndUnparseable() {
        assertThat(HeaderList.fromStoredString(null)).isEmpty();
        assertThat(HeaderList.fromStoredString("   ")).isEmpty();
        assertThat(HeaderList.fromStoredString("no-colon-here")).isEmpty();
    }
}
