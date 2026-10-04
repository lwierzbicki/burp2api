# burp2api Agent Notes

Canonical tool context lives in:

- `README.md`
- `TODO.md`
- `CLAUDE.md` for local agent routing and deviations

This is an OpenJDK 21 Maven project loaded into Burp Suite Professional. Preserve
the `com.burp2api` namespace and keep tests offline by default.

The API handles sensitive Burp traffic and authentication material. Never add
live captured data, databases, tokens, or cookies to tests or fixtures.
