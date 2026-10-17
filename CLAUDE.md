# burp2api

Keep durable behavior in `README.md` or `TODO.md`; use this file
for Claude-specific routing and deviations.

## Project shape

- OpenJDK 21 Maven Burp Suite extension
- Entry point: `com.burp2api.BurpApiExtension`
- Default API port: `7850`
- Default config/state directory: `~/.burp2api/`. The per-project SQLite DB is
  co-located beside the open `.burp` file when one is detectable (from the JVM
  `--project-file` arg); it falls back to `~/.burp2api/` for temporary projects
  or an explicit `BURP2API_DB_PATH`/UI path override.
- Build: `mvn clean package`
- Offline contract test: `python -m unittest tests.test_repository_contract -v`

The API handles sensitive Burp traffic and authentication material. Never add
live captured data, databases, tokens, or cookies to tests or fixtures.
