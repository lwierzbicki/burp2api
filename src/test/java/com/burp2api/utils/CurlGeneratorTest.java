package com.burp2api.utils;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;

/**
 * Ticket #20: {@code /proxy/request/{id}/curl} is fed the stored header blob,
 * which every capture path has written as {@code List<HttpHeader>.toString()}.
 * Re-splitting that on line breaks yields one unusable {@code -H}; it must go
 * through the same parser as every other stored-header reader.
 */
class CurlGeneratorTest {

    private String curlFor(String storedHeaders) {
        CurlGenerator.RequestData request = new CurlGenerator.RequestData(
            "GET", "https://target.example/admin", storedHeaders, null, null);
        return CurlGenerator.buildCurlCommand(request);
    }

    @Test
    void legacyListBlobYieldsOneHeaderFlagPerHeader() {
        String curl = curlFor("[Host: target.example, Accept: text/html, "
            + "Cache-Control: private, max-age=0]");

        assertThat(curl)
            .contains("-H 'accept: text/html'")
            .contains("-H 'cache-control: private, max-age=0'");
        // Host is dropped: curl derives it from the URL.
        assertThat(curl).doesNotContain("host:");
        assertThat(curl.split("-H ", -1)).hasSize(3); // two headers -> two flags
    }

    @Test
    void newlineBlockYieldsTheSameHeaders() {
        String curl = curlFor("Accept: text/html\r\nCache-Control: private, max-age=0");

        assertThat(curl)
            .contains("-H 'accept: text/html'")
            .contains("-H 'cache-control: private, max-age=0'");
    }

    @Test
    void nullAndBlankHeadersProduceNoHeaderFlags() {
        assertThat(curlFor(null)).doesNotContain("-H ");
        assertThat(curlFor("   ")).doesNotContain("-H ");
    }
}
