package com.burp2api.logging;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.core.ToolSource;
import burp.api.montoya.core.ToolType;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.handler.HttpResponseReceived;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.project.Project;
import com.burp2api.config.ApiConfig;
import com.burp2api.database.DatabaseService;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.util.List;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * Ticket #53: standard proxied captures must persist their request and response bodies durably,
 * retrievable byte-exact for both directions, rather than coming back empty.
 *
 * <p>The root cause was a second, lossy writer: {@code ProxyLogger} captured every proxied
 * transaction a second time on a background thread, reading the intercepted message bodies
 * off-thread and correlating the response to its request by a {@code url+method+time-window}
 * heuristic that orphaned request rows under concurrent traffic, leaving them with an empty
 * {@code response_body}. Those empty duplicates interleaved with the complete rows in
 * {@code /proxy/search} and {@code /proxy/history}. The fix routes all Proxy capture through the
 * single synchronous {@link AllToolsLogger} HTTP handler, which snapshots both bodies in the
 * handler thread into one complete row (+ byte-exact raw BLOBs).
 *
 * <p>This test drives {@link AllToolsLogger#handleHttpResponseReceived} with a mocked proxied
 * POST and asserts exactly one {@code proxy_traffic} row carrying both bodies, plus the byte-exact
 * raw capture. A regression that reintroduced a second (empty-bodied) writer would break the
 * single-row assertion; a regression that dropped a body would break the body assertions.
 */
class AllToolsLoggerProxyCaptureTest {

    @TempDir
    Path tempDir;

    private DatabaseService databaseService;
    private AllToolsLogger logger;

    private static final String REQUEST_BODY = "{\"username\":\"alice\",\"role\":\"admin\"}";
    private static final String RESPONSE_BODY = "{\"id\":4242,\"status\":\"created\"}";
    private static final byte[] REQUEST_RAW =
        ("POST /users HTTP/2\r\nHost: target.test\r\n\r\n" + REQUEST_BODY).getBytes(StandardCharsets.UTF_8);
    private static final byte[] RESPONSE_RAW =
        ("HTTP/2 201 Created\r\nContent-Type: application/json\r\n\r\n" + RESPONSE_BODY)
            .getBytes(StandardCharsets.UTF_8);

    @BeforeEach
    void setUp() {
        ApiConfig config = mock(ApiConfig.class);
        when(config.getDatabasePath()).thenReturn(tempDir.resolve("burp2api.db").toString());
        when(config.getSessionTag()).thenReturn("");
        when(config.getMaxStoredContentChars()).thenReturn(10 * 1024 * 1024);
        when(config.getMaxRawBytes()).thenReturn(10 * 1024 * 1024);

        Project project = mock(Project.class);
        when(project.name()).thenReturn("alltools-proxy-capture-test");
        MontoyaApi api = mock(MontoyaApi.class);
        when(api.project()).thenReturn(project);

        databaseService = new DatabaseService(api, config);
        databaseService.initialize();

        // trafficQueue is null: the synchronous DB write happens before the (WebSocket-only)
        // queue hand-off, and AllToolsLogger tolerates a null queue. Keeping it null isolates
        // the test to the single synchronous proxy_traffic write with no background thread.
        logger = new AllToolsLogger(api, databaseService, null, config);
    }

    @AfterEach
    void tearDown() {
        if (databaseService != null) {
            databaseService.shutdown();
        }
    }

    @Test
    void proxiedPostPersistsBothBodiesInOneCompleteRow() throws Exception {
        HttpResponseReceived response = mockProxiedPost();

        // handleHttpResponseReceived captures and stores the transaction, then returns
        // ResponseReceivedAction.continueWith(...) - which needs Burp's internal object factory,
        // absent under plain JUnit. The capture (the code under test) runs and commits before that
        // return, so the persisted row below is authoritative; the factory NPE on the way out is a
        // test-harness artifact, not a capture failure.
        try {
            logger.handleHttpResponseReceived(response);
        } catch (NullPointerException expectedWithoutBurpRuntime) {
            // ObjectFactoryLocator.FACTORY is null outside a running Burp; ignore.
        }

        // Exactly one row - the single synchronous writer, no empty duplicate.
        assertThat(scalarLong("SELECT COUNT(*) FROM proxy_traffic")).isEqualTo(1L);

        try (Connection conn = databaseService.getConnection();
             PreparedStatement stmt = conn.prepareStatement(
                 "SELECT method, url, host, body, response_body, status_code, traffic_source, "
                     + "request_raw, response_raw FROM proxy_traffic");
             ResultSet rs = stmt.executeQuery()) {
            assertThat(rs.next()).isTrue();
            assertThat(rs.getString("method")).isEqualTo("POST");
            assertThat(rs.getString("url")).isEqualTo("https://target.test/users");
            assertThat(rs.getString("host")).isEqualTo("target.test");
            // Both directions persisted, non-empty.
            assertThat(rs.getString("body")).isEqualTo(REQUEST_BODY);
            assertThat(rs.getString("response_body")).isEqualTo(RESPONSE_BODY);
            assertThat(rs.getInt("status_code")).isEqualTo(201);
            assertThat(rs.getString("traffic_source")).isEqualTo("PROXY");
            // Byte-exact raw capture (#24) attached for both directions.
            assertThat(rs.getBytes("request_raw")).isEqualTo(REQUEST_RAW);
            assertThat(rs.getBytes("response_raw")).isEqualTo(RESPONSE_RAW);
        }
    }

    private HttpResponseReceived mockProxiedPost() {
        HttpService service = mock(HttpService.class);
        when(service.host()).thenReturn("target.test");

        ByteArray requestRaw = mock(ByteArray.class);
        when(requestRaw.getBytes()).thenReturn(REQUEST_RAW);
        HttpRequest request = mock(HttpRequest.class);
        when(request.method()).thenReturn("POST");
        when(request.url()).thenReturn("https://target.test/users");
        when(request.httpService()).thenReturn(service);
        when(request.headers()).thenReturn(List.of());
        when(request.bodyToString()).thenReturn(REQUEST_BODY);
        when(request.httpVersion()).thenReturn("HTTP/2");
        when(request.toByteArray()).thenReturn(requestRaw);

        ByteArray responseRaw = mock(ByteArray.class);
        when(responseRaw.getBytes()).thenReturn(RESPONSE_RAW);
        ToolSource toolSource = mock(ToolSource.class);
        when(toolSource.toolType()).thenReturn(ToolType.PROXY);
        HttpResponseReceived response = mock(HttpResponseReceived.class);
        when(response.initiatingRequest()).thenReturn(request);
        when(response.headers()).thenReturn(List.of());
        when(response.bodyToString()).thenReturn(RESPONSE_BODY);
        when(response.statusCode()).thenReturn((short) 201);
        when(response.httpVersion()).thenReturn("HTTP/2");
        when(response.toByteArray()).thenReturn(responseRaw);
        when(response.toolSource()).thenReturn(toolSource);
        return response;
    }

    private long scalarLong(String sql) throws Exception {
        try (Connection conn = databaseService.getConnection();
             PreparedStatement stmt = conn.prepareStatement(sql);
             ResultSet rs = stmt.executeQuery()) {
            rs.next();
            return rs.getLong(1);
        }
    }
}
