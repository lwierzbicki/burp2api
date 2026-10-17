package com.burp2api.database;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.project.Project;
import com.burp2api.config.ApiConfig;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.PreparedStatement;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * Ticket #24: a captured request/response round-trips through storage
 * byte-identical via the {@code request_raw}/{@code response_raw} BLOB columns.
 * The flattened header/body columns cannot do this (comma-valued headers shred,
 * bodies round-trip through an ISO-8859-1 char cap), so raw is the evidence path.
 */
class DatabaseServiceRawCaptureTest {

    @TempDir
    Path tempDir;

    private DatabaseService databaseService;

    @BeforeEach
    void setUp() {
        ApiConfig config = mock(ApiConfig.class);
        when(config.getDatabasePath()).thenReturn(tempDir.resolve("burp2api.db").toString());
        when(config.getSessionTag()).thenReturn("");
        when(config.getMaxStoredContentChars()).thenReturn(10 * 1024 * 1024);
        when(config.getMaxRawBytes()).thenReturn(1024);

        Project project = mock(Project.class);
        when(project.name()).thenReturn("rawcapture-test");
        MontoyaApi api = mock(MontoyaApi.class);
        when(api.project()).thenReturn(project);

        databaseService = new DatabaseService(api, config);
        databaseService.initialize();
    }

    @AfterEach
    void tearDown() {
        if (databaseService != null) {
            databaseService.shutdown();
        }
    }

    /**
     * A request with a comma-valued header and a response body containing a NUL
     * round-trips byte-identical - the two failure modes #24 calls out.
     */
    @Test
    void rawBytesRoundTripByteIdentical() {
        long id = insertRow(100L);

        // A raw request whose header value contains ", " followed by something
        // header-shaped - exactly what the flattened-blob parser shreds.
        byte[] requestRaw = ("GET /x HTTP/1.1\r\n"
            + "Host: proxy.test\r\n"
            + "X-Thing: alpha, Retry-After: 5\r\n"
            + "Accept: text/html, application/xml\r\n\r\n")
            .getBytes(StandardCharsets.ISO_8859_1);
        // A response body with an embedded NUL and high bytes - LIKE/length() over
        // the TEXT column would stop at the NUL; the BLOB keeps every byte.
        byte[] responseRaw = new byte[] {
            'H', 'T', 'T', 'P', '/', '1', '.', '1', ' ', '2', '0', '0', '\r', '\n',
            'C', 'T', ':', 'x', '\r', '\n', '\r', '\n',
            0x00, (byte) 0xFF, (byte) 0x80, 'e', 'n', 'd'
        };

        databaseService.setRawBytes(id, requestRaw, responseRaw);

        DatabaseService.RawCaptureRow row = databaseService.getRawCapture(id);
        assertThat(row).isNotNull();
        assertThat(row.requestRaw).isEqualTo(requestRaw);
        assertThat(row.responseRaw).isEqualTo(responseRaw);
        assertThat(row.requestRawOmitted).isFalse();
        assertThat(row.responseRawOmitted).isFalse();
    }

    /** A message over the cap is stored NULL and flagged, never truncated. */
    @Test
    void oversizeRawIsOmittedNotTruncated() {
        long id = insertRow(101L);
        byte[] huge = new byte[2048]; // cap is 1024 in this test

        databaseService.setRawBytes(id, huge, null);

        DatabaseService.RawCaptureRow row = databaseService.getRawCapture(id);
        assertThat(row).isNotNull();
        assertThat(row.requestRaw).isNull();
        assertThat(row.requestRawOmitted).isTrue();
    }

    /** A response-only update must not clear a request already captured. */
    @Test
    void responseOnlyUpdateKeepsExistingRequestRaw() {
        long id = insertRow(102L);
        byte[] requestRaw = "REQ".getBytes(StandardCharsets.ISO_8859_1);
        byte[] responseRaw = "RESP".getBytes(StandardCharsets.ISO_8859_1);

        databaseService.setRawBytes(id, requestRaw, null);
        databaseService.setRawBytes(id, null, responseRaw);

        DatabaseService.RawCaptureRow row = databaseService.getRawCapture(id);
        assertThat(row.requestRaw).isEqualTo(requestRaw);
        assertThat(row.responseRaw).isEqualTo(responseRaw);
    }

    /** A row that never got raw bytes reports absent, not omitted. */
    @Test
    void preMigrationRowReportsAbsentNotOmitted() {
        long id = insertRow(103L);

        DatabaseService.RawCaptureRow row = databaseService.getRawCapture(id);
        assertThat(row).isNotNull();
        assertThat(row.requestRaw).isNull();
        assertThat(row.responseRaw).isNull();
        assertThat(row.requestRawOmitted).isFalse();
        assertThat(row.responseRawOmitted).isFalse();
    }

    @Test
    void getRawCaptureReturnsNullForUnknownId() {
        assertThat(databaseService.getRawCapture(999_999L)).isNull();
    }

    private long insertRow(long id) {
        try {
            Connection conn = databaseService.getConnection();
            try (PreparedStatement stmt = conn.prepareStatement(
                    "INSERT INTO proxy_traffic (id, timestamp, method, url, host) "
                        + "VALUES (?, ?, ?, ?, ?)")) {
                stmt.setLong(1, id);
                stmt.setLong(2, 1_700_000_000_000L);
                stmt.setString(3, "GET");
                stmt.setString(4, "http://proxy.test/x");
                stmt.setString(5, "proxy.test");
                stmt.executeUpdate();
            }
            return id;
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}
