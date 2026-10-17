package com.burp2api.utils;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

class CookieReconstructorTest {

    @Test
    void parsesCookieRequestHeaderIntoOrderedPairs() {
        String headers = "GET / HTTP/1.1\nHost: app.example.com\n"
            + "Cookie: sid=abc123; theme=dark; csrf=tok\n";

        Map<String, String> cookies = CookieReconstructor.parseRequestCookieHeader(headers);

        assertThat(cookies).containsExactly(
            Map.entry("sid", "abc123"),
            Map.entry("theme", "dark"),
            Map.entry("csrf", "tok"));
    }

    @Test
    void parsesSetCookieAttributesAndDeletionMarkers() {
        String responseHeaders = "HTTP/1.1 200 OK\n"
            + "Set-Cookie: sid=newval; Domain=.example.com; Path=/app; Secure; HttpOnly\n"
            + "Set-Cookie: old=; Max-Age=0\n";

        List<CookieReconstructor.SetCookieAttrs> parsed =
            CookieReconstructor.parseSetCookieHeaders(responseHeaders);

        assertThat(parsed).hasSize(2);
        CookieReconstructor.SetCookieAttrs sid = parsed.get(0);
        assertThat(sid.name).isEqualTo("sid");
        assertThat(sid.value).isEqualTo("newval");
        assertThat(sid.domain).isEqualTo("example.com");
        assertThat(sid.path).isEqualTo("/app");
        assertThat(sid.secure).isTrue();
        assertThat(sid.httpOnly).isTrue();
        assertThat(sid.deleted).isFalse();
        assertThat(parsed.get(1).deleted).isTrue();
    }

    @Test
    void mostRecentRequestCookieValueWins() {
        // Newest first: the live jar value is "v2".
        List<CookieReconstructor.Exchange> exchanges = List.of(
            new CookieReconstructor.Exchange("Cookie: sid=v2\n", null),
            new CookieReconstructor.Exchange("Cookie: sid=v1\n", null));

        CookieReconstructor.Result result =
            CookieReconstructor.reconstruct("app.example.com", exchanges);

        assertThat(result.cookies()).hasSize(1);
        assertThat(result.cookies().get(0).value()).isEqualTo("v2");
        assertThat(result.cookies().get(0).source()).isEqualTo("request");
        assertThat(result.cookieHeader()).isEqualTo("sid=v2");
    }

    @Test
    void enrichesRequestCookiesWithSetCookieAttributesAndReplayHeader() {
        List<CookieReconstructor.Exchange> exchanges = List.of(
            new CookieReconstructor.Exchange(
                "Cookie: sid=abc; theme=dark\n",
                "Set-Cookie: sid=abc; Domain=app.example.com; Path=/; Secure; HttpOnly\n"));

        CookieReconstructor.Result result =
            CookieReconstructor.reconstruct("app.example.com", exchanges);

        CookieReconstructor.Cookie sid = result.cookies().stream()
            .filter(c -> c.name().equals("sid")).findFirst().orElseThrow();
        assertThat(sid.secure()).isTrue();
        assertThat(sid.httpOnly()).isTrue();
        assertThat(sid.domain()).isEqualTo("app.example.com");

        CookieReconstructor.Cookie theme = result.cookies().stream()
            .filter(c -> c.name().equals("theme")).findFirst().orElseThrow();
        assertThat(theme.domain()).isEqualTo("app.example.com"); // defaulted to host
        assertThat(theme.path()).isEqualTo("/");

        assertThat(result.cookieHeader()).isEqualTo("sid=abc; theme=dark");
    }

    @Test
    void fallsBackToSetCookieValueWhenNeverEchoedInRequest() {
        List<CookieReconstructor.Exchange> exchanges = List.of(
            new CookieReconstructor.Exchange(
                null,
                "Set-Cookie: fresh=justset; Path=/\n"));

        CookieReconstructor.Result result =
            CookieReconstructor.reconstruct("app.example.com", exchanges);

        assertThat(result.cookies()).hasSize(1);
        assertThat(result.cookies().get(0).name()).isEqualTo("fresh");
        assertThat(result.cookies().get(0).value()).isEqualTo("justset");
        assertThat(result.cookies().get(0).source()).isEqualTo("response");
    }

    @Test
    void ignoresDeletedSetCookieWithoutRequestValue() {
        List<CookieReconstructor.Exchange> exchanges = List.of(
            new CookieReconstructor.Exchange(
                null,
                "Set-Cookie: gone=; Max-Age=0\n"));

        CookieReconstructor.Result result =
            CookieReconstructor.reconstruct("app.example.com", exchanges);

        assertThat(result.cookies()).isEmpty();
        assertThat(result.cookieHeader()).isEmpty();
    }

    @Test
    void handlesEmptyInputSafely() {
        CookieReconstructor.Result result =
            CookieReconstructor.reconstruct("app.example.com", List.of());

        assertThat(result.cookies()).isEmpty();
        assertThat(result.cookieHeader()).isEmpty();
    }

    // Regression for #1: the captured-traffic store serialises headers with
    // List.toString(), e.g. "[Host: h, Cookie: a=b; c=d, Accept: x, y]" on a
    // single line. The reconstructor previously split only on newlines and
    // returned zero cookies for this format.
    @Test
    void parsesCookieFromBracketedListToStringHeaders() {
        String headers = "[Host: app.meticulous.ai, "
            + "Cookie: meticulous.sid=s%3Aabc.def; ajs_anonymous_id=xyz, "
            + "Accept: text/html, application/xhtml+xml, "
            + "Accept-Encoding: gzip, deflate, br]";

        Map<String, String> cookies = CookieReconstructor.parseRequestCookieHeader(headers);

        assertThat(cookies).containsExactly(
            Map.entry("meticulous.sid", "s%3Aabc.def"),
            Map.entry("ajs_anonymous_id", "xyz"));
    }

    @Test
    void reconstructsSessionFromBracketedCapturedTrafficFormat() {
        // Exactly the shape stored in proxy_traffic.headers / response_headers.
        List<CookieReconstructor.Exchange> exchanges = List.of(
            new CookieReconstructor.Exchange(
                "[Host: app.meticulous.ai, "
                    + "Cookie: meticulous.sid=s%3Alive.token; ajs_user_id=u123, "
                    + "Accept: text/html, application/json]",
                "[Content-Type: application/json, "
                    + "Set-Cookie: meticulous.sid=s%3Alive.token; Path=/; Secure; HttpOnly]"));

        CookieReconstructor.Result result =
            CookieReconstructor.reconstruct("app.meticulous.ai", exchanges);

        CookieReconstructor.Cookie sid = result.cookies().stream()
            .filter(c -> c.name().equals("meticulous.sid")).findFirst().orElseThrow();
        assertThat(sid.value()).isEqualTo("s%3Alive.token");
        assertThat(sid.secure()).isTrue();
        assertThat(sid.httpOnly()).isTrue();
        assertThat(result.cookieHeader()).contains("meticulous.sid=s%3Alive.token");
    }
}
