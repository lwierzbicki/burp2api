package com.burp2api.utils;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import burp.api.montoya.http.message.requests.HttpRequest;
import com.burp2api.utils.HeaderInput.Header;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

/**
 * Ticket #8: {@code headers} must be accepted as a JSON object (and array of
 * pairs) in addition to the legacy CRLF string, without a 500. Covers the
 * type-branching parser for object, string, array, empty, and missing inputs.
 */
class HeaderInputTest {

    @Test
    void parsesJsonObjectFormPreservingOrder() {
        Map<String, Object> raw = new LinkedHashMap<>();
        raw.put("User-Agent", "x");
        raw.put("Referer", "https://example.com/");

        List<Header> headers = HeaderInput.parse(raw);

        assertThat(headers).containsExactly(
            new Header("User-Agent", "x"),
            new Header("Referer", "https://example.com/"));
    }

    @Test
    void parsesLegacyCrlfStringForm() {
        List<Header> headers = HeaderInput.parse(
            "User-Agent: x\r\nHost: example.com:8443\nReferer: https://example.com/");

        assertThat(headers).containsExactly(
            new Header("User-Agent", "x"),
            // value keeps everything after the first colon
            new Header("Host", "example.com:8443"),
            new Header("Referer", "https://example.com/"));
    }

    @Test
    void parsesArrayOfPairsFormForMultiValueControl() {
        List<List<String>> raw = List.of(
            List.of("Accept", "text/html"),
            List.of("X-Debug", "1"));

        List<Header> headers = HeaderInput.parse(raw);

        assertThat(headers).containsExactly(
            new Header("Accept", "text/html"),
            new Header("X-Debug", "1"));
    }

    @Test
    void coercesNonStringObjectValues() {
        Map<String, Object> raw = new LinkedHashMap<>();
        raw.put("X-Count", 3);
        raw.put("X-Enabled", true);

        List<Header> headers = HeaderInput.parse(raw);

        assertThat(headers).containsExactly(
            new Header("X-Count", "3"),
            new Header("X-Enabled", "true"));
    }

    @Test
    void skipsBlankNames() {
        List<Header> headers = HeaderInput.parse("   : value\r\nGood: ok");

        assertThat(headers).containsExactly(new Header("Good", "ok"));
    }

    @Test
    void emptyStringAndNullYieldNoHeaders() {
        assertThat(HeaderInput.parse("")).isEmpty();
        assertThat(HeaderInput.parse(null)).isEmpty();
        assertThat(HeaderInput.parse(Map.of())).isEmpty();
    }

    @Test
    void toBlockRoundTripsThroughParse() {
        List<Header> headers = HeaderInput.parse(Map.of("A", "1"));
        String block = HeaderInput.toBlock(
            List.of(new Header("A", "1"), new Header("B", "2")));

        assertThat(block).isEqualTo("A: 1\r\nB: 2");
        assertThat(HeaderInput.toBlock(headers)).isEqualTo("A: 1");
        assertThat(HeaderInput.toBlock(List.of())).isEmpty();
    }

    @Test
    void applyToAddsAbsentHeadersAndUpdatesPresentOnesLastWins() {
        HttpRequest req = mock(HttpRequest.class);
        // User-Agent is absent; the second value for the same name updates.
        when(req.hasHeader("User-Agent")).thenReturn(false).thenReturn(true);
        when(req.hasHeader("Referer")).thenReturn(false);
        when(req.withAddedHeader(eq("User-Agent"), eq("x"))).thenReturn(req);
        when(req.withUpdatedHeader(eq("User-Agent"), eq("y"))).thenReturn(req);
        when(req.withAddedHeader(eq("Referer"), eq("https://example.com/"))).thenReturn(req);

        HttpRequest result = HeaderInput.applyTo(req, List.of(
            new Header("User-Agent", "x"),
            new Header("User-Agent", "y"),
            new Header("Referer", "https://example.com/")));

        assertThat(result).isSameAs(req);
        verify(req).withAddedHeader("User-Agent", "x");
        verify(req).withUpdatedHeader("User-Agent", "y");
        verify(req).withAddedHeader("Referer", "https://example.com/");
    }
}
