package com.burp2api.handlers;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;

/**
 * A malformed {@code url} on /proxy/send (e.g. an agent that passes a CLI-style
 * token like {@code "--help"}) used to reach {@code httpRequestFromUrl()} and
 * surface as a 500 + stack trace. {@link RouteHandler#validateHttpUrl} now
 * rejects non-URL input so the route can answer with a clean 400.
 */
class RouteHandlerUrlValidationTest {

    @Test
    void acceptsAbsoluteHttpAndHttpsUrls() {
        assertThat(RouteHandler.validateHttpUrl("https://h2.example/api")).isNull();
        assertThat(RouteHandler.validateHttpUrl("http://127.0.0.1:7850/path?q=1")).isNull();
        assertThat(RouteHandler.validateHttpUrl("  https://h2.example/api  ")).isNull();
    }

    @Test
    void rejectsCliStyleTokenPassedAsUrl() {
        assertThat(RouteHandler.validateHttpUrl("--help"))
            .contains("absolute http");
    }

    @Test
    void rejectsNullBlankAndSchemeless() {
        assertThat(RouteHandler.validateHttpUrl(null)).contains("required");
        assertThat(RouteHandler.validateHttpUrl("   ")).contains("required");
        assertThat(RouteHandler.validateHttpUrl("h2.example/api")).contains("absolute http");
    }

    @Test
    void rejectsNonHttpSchemes() {
        assertThat(RouteHandler.validateHttpUrl("ftp://h2.example/x")).contains("absolute http");
        assertThat(RouteHandler.validateHttpUrl("file:///etc/passwd")).contains("absolute http");
    }

    @Test
    void rejectsHttpUrlWithoutHost() {
        assertThat(RouteHandler.validateHttpUrl("http:///no-host")).contains("host");
    }

    @Test
    void rejectsIllegalUriCharacters() {
        assertThat(RouteHandler.validateHttpUrl("http://exa mple/x")).isNotNull();
    }
}
