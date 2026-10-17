package com.burp2api.utils;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;
import org.junit.jupiter.api.Test;

class SessionCookieJarTest {

    // --- Task 1: update, last-write-wins, deletion, tag isolation ---

    @Test
    void storesCookieFromSetCookieHeader() {
        SessionCookieJar jar = new SessionCookieJar();

        jar.update("s", "app.example.com",
            "HTTP/1.1 200 OK\nSet-Cookie: sid=abc; Path=/\n");

        assertThat(jar.snapshot("s")).singleElement().satisfies(c -> {
            assertThat(c.name()).isEqualTo("sid");
            assertThat(c.value()).isEqualTo("abc");
        });
    }

    @Test
    void rotationReplacesValueForSameNameDomainPath() {
        SessionCookieJar jar = new SessionCookieJar();

        jar.update("s", "app.example.com",
            "HTTP/1.1 200 OK\nSet-Cookie: __session=v1; Path=/\n");
        jar.update("s", "app.example.com",
            "HTTP/1.1 200 OK\nSet-Cookie: __session=v2; Path=/\n");

        assertThat(jar.snapshot("s")).singleElement().satisfies(c -> {
            assertThat(c.name()).isEqualTo("__session");
            assertThat(c.value()).isEqualTo("v2");
        });
    }

    @Test
    void deletionMarkerRemovesCookie() {
        SessionCookieJar jar = new SessionCookieJar();

        jar.update("s", "app.example.com",
            "HTTP/1.1 200 OK\nSet-Cookie: sid=abc; Path=/\n");
        jar.update("s", "app.example.com",
            "HTTP/1.1 200 OK\nSet-Cookie: sid=; Path=/; Max-Age=0\n");

        assertThat(jar.snapshot("s")).isEmpty();
    }

    @Test
    void tagsAreIsolated() {
        SessionCookieJar jar = new SessionCookieJar();

        jar.update("A", "app.example.com",
            "HTTP/1.1 200 OK\nSet-Cookie: sid=a; Path=/\n");

        assertThat(jar.snapshot("A")).hasSize(1);
        assertThat(jar.snapshot("B")).isEmpty();
    }

    // --- Task 2: apply/merge (domain, path, secure, caller precedence) ---

    @Test
    void hostOnlyCookieSentToExactHostNotSubdomain() {
        SessionCookieJar jar = new SessionCookieJar();
        jar.update("s", "example.com",
            "HTTP/1.1 200 OK\nSet-Cookie: sid=abc; Path=/\n");

        assertThat(jar.buildCookieHeader("s", "example.com", "/", true, null))
            .isEqualTo("sid=abc");
        assertThat(jar.buildCookieHeader("s", "app.example.com", "/", true, null))
            .isEmpty();
    }

    @Test
    void domainCookieSentToSubdomain() {
        SessionCookieJar jar = new SessionCookieJar();
        jar.update("s", "example.com",
            "HTTP/1.1 200 OK\nSet-Cookie: sid=abc; Domain=.example.com; Path=/\n");

        assertThat(jar.buildCookieHeader("s", "app.example.com", "/", true, null))
            .isEqualTo("sid=abc");
    }

    @Test
    void pathPrefixIsHonored() {
        SessionCookieJar jar = new SessionCookieJar();
        jar.update("s", "example.com",
            "HTTP/1.1 200 OK\nSet-Cookie: sid=abc; Path=/app\n");

        assertThat(jar.buildCookieHeader("s", "example.com", "/app/page", true, null))
            .isEqualTo("sid=abc");
        assertThat(jar.buildCookieHeader("s", "example.com", "/", true, null))
            .isEmpty();
        // Boundary: /app must not match /apple.
        assertThat(jar.buildCookieHeader("s", "example.com", "/apple", true, null))
            .isEmpty();
    }

    @Test
    void secureCookieOmittedOverHttp() {
        SessionCookieJar jar = new SessionCookieJar();
        jar.update("s", "example.com",
            "HTTP/1.1 200 OK\nSet-Cookie: sid=abc; Path=/; Secure\n");

        assertThat(jar.buildCookieHeader("s", "example.com", "/", false, null)).isEmpty();
        assertThat(jar.buildCookieHeader("s", "example.com", "/", true, null))
            .isEqualTo("sid=abc");
    }

    @Test
    void callerCookieOverridesJarValue() {
        SessionCookieJar jar = new SessionCookieJar();
        jar.update("s", "example.com",
            "HTTP/1.1 200 OK\nSet-Cookie: x=stored; Path=/\n");

        assertThat(jar.buildCookieHeader("s", "example.com", "/", true, "x=override"))
            .isEqualTo("x=override");
    }

    @Test
    void emptyJarReturnsCallerCookieUnchanged() {
        SessionCookieJar jar = new SessionCookieJar();

        assertThat(jar.buildCookieHeader("s", "example.com", "/", true, "a=1; b=2"))
            .isEqualTo("a=1; b=2");
    }

    @Test
    void jarAndCallerCookiesAreMerged() {
        SessionCookieJar jar = new SessionCookieJar();
        jar.update("s", "example.com",
            "HTTP/1.1 200 OK\nSet-Cookie: sid=abc; Path=/\n");

        assertThat(jar.buildCookieHeader("s", "example.com", "/", true, "caller=1"))
            .isEqualTo("caller=1; sid=abc");
    }

    @Test
    void resetClearsTagJar() {
        SessionCookieJar jar = new SessionCookieJar();
        jar.update("s", "example.com",
            "HTTP/1.1 200 OK\nSet-Cookie: sid=abc; Path=/\n");

        jar.reset("s");

        assertThat(jar.snapshot("s")).isEmpty();
    }

    @Test
    void seedAddsReconstructedCookies() {
        SessionCookieJar jar = new SessionCookieJar();
        List<CookieReconstructor.Cookie> seeds = List.of(
            new CookieReconstructor.Cookie("sid", "abc", "example.com", "/",
                true, true, "request"));

        int added = jar.seed("s", seeds);

        assertThat(added).isEqualTo(1);
        assertThat(jar.buildCookieHeader("s", "example.com", "/", true, null))
            .isEqualTo("sid=abc");
    }
}
