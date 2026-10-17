package com.burp2api.database;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.File;
import org.junit.jupiter.api.Test;

/**
 * The project database used to accumulate in {@code ~/.burp2api}, filling the home directory with
 * large per-project SQLite files that were not held with the engagement. When a disk-based Burp
 * project ({@code .burp}) is open, the database should instead sit beside the project file so it
 * travels with the project — unless the user has explicitly overridden the database directory.
 */
class DatabaseServiceDbPathTest {

    private static final String DEFAULT_STATE_DIR =
            System.getProperty("user.home") + File.separator + ".burp2api";

    @Test
    void coLocatesDatabaseWithProjectFileWhenUsingDefaultDir() {
        String base = DEFAULT_STATE_DIR + File.separator + "burp2api.db";

        String path = DatabaseService.resolveProjectDatabasePath(
                base, "Acme_Engagement", "/cases/acme/acme.burp", DEFAULT_STATE_DIR);

        assertThat(path).isEqualTo(new File("/cases/acme").getAbsolutePath()
                + File.separator + "burp2api_Acme_Engagement.db");
    }

    @Test
    void fallsBackToConfiguredDirForTemporaryProject() {
        String base = DEFAULT_STATE_DIR + File.separator + "burp2api.db";

        String path = DatabaseService.resolveProjectDatabasePath(
                base, "Temporary_Project", null, DEFAULT_STATE_DIR);

        assertThat(path).isEqualTo(DEFAULT_STATE_DIR
                + File.separator + "burp2api_Temporary_Project.db");
    }

    @Test
    void respectsExplicitDirectoryOverrideEvenWithProjectFileOpen() {
        String base = "/data/burp-dbs/burp2api.db";

        String path = DatabaseService.resolveProjectDatabasePath(
                base, "Acme", "/cases/acme/acme.burp", DEFAULT_STATE_DIR);

        assertThat(path).isEqualTo("/data/burp-dbs" + File.separator + "burp2api_Acme.db");
    }

    @Test
    void extractsProjectFileFromEqualsForm() {
        String[] args = {"-jar", "burpsuite.jar", "--project-file=/cases/acme/acme.burp"};

        assertThat(DatabaseService.extractProjectFileFromArgs(args))
                .isEqualTo("/cases/acme/acme.burp");
    }

    @Test
    void extractsProjectFileFromSeparateTokenForm() {
        String[] args = {"--project-file", "/cases/acme/acme.burp", "--unpause-spider-and-scanner"};

        assertThat(DatabaseService.extractProjectFileFromArgs(args))
                .isEqualTo("/cases/acme/acme.burp");
    }

    @Test
    void extractsQuotedProjectFilePath() {
        String[] args = {"--project-file=\"/cases/acme project/acme.burp\""};

        assertThat(DatabaseService.extractProjectFileFromArgs(args))
                .isEqualTo("/cases/acme project/acme.burp");
    }

    @Test
    void extractsBarePositionalProjectFile() {
        String[] args = {"-jar", "burpsuite.jar", "/cases/acme/acme.burp"};

        assertThat(DatabaseService.extractProjectFileFromArgs(args))
                .isEqualTo("/cases/acme/acme.burp");
    }

    @Test
    void returnsNullWhenNoProjectFilePresent() {
        String[] args = {"-jar", "burpsuite.jar", "--config-file=/tmp/config.json"};

        assertThat(DatabaseService.extractProjectFileFromArgs(args)).isNull();
        assertThat(DatabaseService.extractProjectFileFromArgs(null)).isNull();
    }
}
