import json
import re
import unittest
from pathlib import Path


TOOL_ROOT = Path(__file__).resolve().parents[1]
REPO_ROOT = TOOL_ROOT.parent

ROUTE_HANDLER = TOOL_ROOT / "src/main/java/com/burp2api/handlers/RouteHandler.java"

# Registered routes that are deliberately not advertised in the endpoint
# catalog: a dev-only route returning a hardcoded list, and a Swagger UI asset.
UNDOCUMENTED_ROUTES = {
    ("GET", "/debug/routes"),
    ("GET", "/docs/swagger-ui.css"),
}


def _registered_routes():
    """Every Javalin route registered across the Java sources."""
    routes = set()
    for path in (TOOL_ROOT / "src/main/java").rglob("*.java"):
        source = path.read_text(encoding="utf-8")
        for match in re.finditer(
            r'app\.(get|post|put|delete|patch)\(\s*"([^"]+)"', source
        ):
            routes.add((match.group(1).upper(), match.group(2)))
    return routes


def _catalog_entries():
    """The (method, path) pairs in RouteHandler.getEndpointList()."""
    source = ROUTE_HANDLER.read_text(encoding="utf-8")
    start = source.index("private List<Map<String, String>> getEndpointList()")
    end = source.index("\n    }\n", start)
    return {
        (match.group(1).upper(), match.group(2))
        for match in re.finditer(
            r'Map\.of\("method",\s*"(\w+)",\s*"path",\s*"([^"]+)"', source[start:end]
        )
    }


def _snapshot_operations():
    """The (method, path) pairs in the committed OpenAPI snapshot."""
    snapshot = json.loads(
        (TOOL_ROOT / "docs/openapi.json").read_text(encoding="utf-8")
    )
    return {
        (method.upper(), path)
        for path, operations in snapshot["paths"].items()
        for method in operations
    }



class Burp2ApiRepositoryContractTests(unittest.TestCase):
    def test_maven_and_java_surfaces_use_burp2api_name(self):
        pom = (TOOL_ROOT / "pom.xml").read_text(encoding="utf-8")
        entrypoint = (
            TOOL_ROOT
            / "src/main/java/com/burp2api/BurpApiExtension.java"
        ).read_text(encoding="utf-8")

        self.assertIn("<groupId>com.burp2api</groupId>", pom)
        self.assertIn("<artifactId>burp2api</artifactId>", pom)
        self.assertIn("<mainClass>com.burp2api.BurpApiExtension</mainClass>", pom)
        self.assertIn("package com.burp2api;", entrypoint)
        self.assertIn('EXTENSION_NAME = "burp2api"', entrypoint)

        java_sources = list((TOOL_ROOT / "src/main/java").rglob("*.java"))
        self.assertTrue(java_sources)
        mismatched_namespace = [
            str(path.relative_to(TOOL_ROOT))
            for path in java_sources
            if not re.search(
                r"^package com\.burp2api(?:\.|;)",
                path.read_text(encoding="utf-8"),
                re.MULTILINE,
            )
        ]
        self.assertEqual([], mismatched_namespace)

    def test_tool_is_documented_in_repository_catalog(self):
        root_readme = (TOOL_ROOT / "README.md").read_text(encoding="utf-8")
        self.assertIn("# burp2api", root_readme)

    def test_openapi_snapshot_is_valid_and_renamed(self):
        snapshot = json.loads(
            (TOOL_ROOT / "docs/openapi.json").read_text(encoding="utf-8")
        )

        self.assertEqual("3.0.3", snapshot["openapi"])
        self.assertEqual(
            "burp2api - Burp Suite REST API Extension",
            snapshot["info"]["title"],
        )
        self.assertEqual("1.1.0", snapshot["info"]["version"])

    def test_openapi_snapshot_reflects_trimmed_surface(self):
        snapshot = json.loads(
            (TOOL_ROOT / "docs/openapi.json").read_text(encoding="utf-8")
        )
        paths = snapshot["paths"]

        # Trimmed enterprise/cruft groups must not be advertised.
        trimmed_prefixes = (
            "/webhooks",
            "/queue",
            "/performance",
            "/database",
            "/user/preferences",
            "/api/version",
            "/scanner/report",
            "/collaborator/analytics",
            "/collaborator/patterns",
            "/collaborator/alerts",
        )
        leaked = [
            path
            for path in paths
            if any(path.startswith(prefix) for prefix in trimmed_prefixes)
        ]
        self.assertEqual([], leaked)

        # Core agent-facing endpoints must remain.
        for required in (
            "/health",
            "/proxy/search",
            "/proxy/send",
            "/scope/check",
            "/scanner/issues",
            "/collaborator/payloads",
            "/auth/cookies",
        ):
            self.assertIn(required, paths)

    def test_every_registered_route_is_in_the_endpoint_catalog(self):
        undocumented = sorted(
            _registered_routes() - _catalog_entries() - UNDOCUMENTED_ROUTES
        )
        self.assertEqual(
            [],
            undocumented,
            "routes registered but missing from RouteHandler.getEndpointList(); "
            "add a catalog entry or list them in UNDOCUMENTED_ROUTES",
        )

    def test_openapi_snapshot_covers_the_endpoint_catalog(self):
        missing = sorted(_catalog_entries() - _snapshot_operations())
        self.assertEqual(
            [],
            missing,
            "catalog entries absent from docs/openapi.json; the snapshot is "
            "hand-enriched, so add the missing operations without regenerating "
            "the file wholesale",
        )

    def test_extension_supports_loopback_bind_and_token_auth(self):
        config = (
            TOOL_ROOT / "src/main/java/com/burp2api/config/ApiConfig.java"
        ).read_text(encoding="utf-8")

        self.assertIn('DEFAULT_BIND_HOST = "127.0.0.1"', config)
        self.assertIn("BURP2API_BIND", config)
        self.assertIn("BURP2API_TOKEN", config)
        self.assertIn("isAuthEnabled", config)

        properties = (
            TOOL_ROOT / "src/main/resources/config/application.properties"
        ).read_text(encoding="utf-8")
        self.assertIn("api.bind=127.0.0.1", properties)
        self.assertIn("api.token=", properties)

    def test_default_port_is_consistent_across_all_surfaces(self):
        """#25: the documented default port must equal the runtime default in
        every place the default is expressed, and the historically-wrong 8989
        must never reappear. A single authoritative value (ApiConfig's
        DEFAULT_PORT) is compared against each derived surface."""
        config = (
            TOOL_ROOT / "src/main/java/com/burp2api/config/ApiConfig.java"
        ).read_text(encoding="utf-8")
        match = re.search(r"DEFAULT_PORT\s*=\s*(\d+)", config)
        self.assertIsNotNone(match, "ApiConfig.DEFAULT_PORT not found")
        port = match.group(1)

        # Bundled config default.
        properties = (
            TOOL_ROOT / "src/main/resources/config/application.properties"
        ).read_text(encoding="utf-8")
        self.assertIn(f"api.port={port}", properties)

        # UI spinner default (both the model and the reset value).
        panel = (
            TOOL_ROOT / "src/main/java/com/burp2api/ui/ConfigurationPanel.java"
        ).read_text(encoding="utf-8")
        self.assertIn(f"SpinnerNumberModel({port},", panel)

        # Operator-facing docs.
        readme = (TOOL_ROOT / "README.md").read_text(encoding="utf-8")
        self.assertIn(f"listen port (default `{port}`)", readme)
        self.assertIn(f"127.0.0.1:{port}", readme)

        claude = (TOOL_ROOT / "CLAUDE.md").read_text(encoding="utf-8")
        self.assertIn(f"Default API port: `{port}`", claude)

        # OpenAPI server URL.
        snapshot = (TOOL_ROOT / "docs/openapi.json").read_text(encoding="utf-8")
        self.assertIn(f"http://localhost:{port}", snapshot)

        # Regression guard: the wrong value from the engagement retrospective
        # must not appear anywhere in the tool tree.
        for path in TOOL_ROOT.rglob("*"):
            if path.is_file() and path.suffix in {
                ".java", ".md", ".properties", ".json", ".xml", ".py"
            } and "target" not in path.parts and "tests" not in path.parts:
                self.assertNotIn(
                    "8989",
                    path.read_text(encoding="utf-8", errors="ignore"),
                    f"stale default port 8989 found in {path.relative_to(TOOL_ROOT)}",
                )

    def test_health_endpoint_surfaces_port_bind_and_version(self):
        """#25: /health echoes the live port/host/version so a caller who
        reaches the service can confirm it, and the OpenAPI schema documents it."""
        route_handler = ROUTE_HANDLER.read_text(encoding="utf-8")
        health = route_handler[route_handler.index('app.get("/health"'):]
        health = health[: health.index("});")]
        self.assertIn('response.put("port", config.getPort())', health)
        self.assertIn('response.put("bind", config.getBindHost())', health)
        self.assertIn(
            'response.put("version", BurpApiExtension.getVersion())', health
        )

        snapshot = json.loads(
            (TOOL_ROOT / "docs/openapi.json").read_text(encoding="utf-8")
        )
        schema = snapshot["paths"]["/health"]["get"]["responses"]["200"][
            "content"
        ]["application/json"]["schema"]
        for field in ("port", "bind", "version"):
            self.assertIn(field, schema.get("properties", {}))

    def test_version_endpoint_surfaces_schema_version(self):
        """#26: /version reports the build's schema_version alongside
        api_version so an operator can tell whether their jar has the
        byte-exact raw-capture fix (schema >= 12), and OpenAPI documents it."""
        route_handler = ROUTE_HANDLER.read_text(encoding="utf-8")
        version_block = route_handler[route_handler.index('app.get("/version"'):]
        version_block = version_block[: version_block.index("});")]
        self.assertIn('response.put("schema_version"', version_block)

        snapshot = json.loads(
            (TOOL_ROOT / "docs/openapi.json").read_text(encoding="utf-8")
        )
        schema = snapshot["paths"]["/version"]["get"]["responses"]["200"][
            "content"
        ]["application/json"]["schema"]
        for field in ("api_version", "schema_version"):
            self.assertIn(field, schema.get("properties", {}))

    def test_proxy_history_response_envelope_is_documented(self):
        """#26: the README documents that /proxy/history returns its rows
        under a `history` key (not `results`) and that the per-row status
        field is `status_code`, the two shape surprises the ticket calls out."""
        readme = (TOOL_ROOT / "README.md").read_text(encoding="utf-8")
        self.assertIn("returns its rows under a `history` key", readme)
        self.assertIn("`status_code` (not `status`)", readme)

    def test_startup_logs_the_listen_url(self):
        """#25: the actual listen URL is surfaced prominently at startup."""
        entrypoint = (
            TOOL_ROOT / "src/main/java/com/burp2api/BurpApiExtension.java"
        ).read_text(encoding="utf-8")
        self.assertIn("config.getBindHost()", entrypoint)
        self.assertIn("listening on", entrypoint)

    def test_curl_endpoint_resolves_both_id_spaces_and_reports_misses(self):
        """#22: GET /proxy/request/{id}/curl must resolve the same public
        proxy_traffic.id space /proxy/search returns, fall back to an internal
        traffic_meta id via its proxy_traffic_id link, surface how it resolved,
        and answer a miss with an actionable error rather than a bare 404."""
        db = (
            TOOL_ROOT
            / "src/main/java/com/burp2api/database/DatabaseService.java"
        ).read_text(encoding="utf-8")

        # Curl lookup reads the public proxy_traffic.id space (same as search).
        curl_lookup = db[db.index("public Map<String, Object> getFullRequestDataForCurl"):]
        curl_lookup = curl_lookup[: curl_lookup.index("\n    public ", 1)]
        self.assertIn("readCurlRow", curl_lookup)
        self.assertIn("linkedProxyTrafficId", curl_lookup)
        self.assertIn('record.put("resolved_via", "id")', curl_lookup)
        self.assertIn('record.put("resolved_via", "traffic_meta_id")', curl_lookup)

        # readCurlRow queries proxy_traffic by id — the id /proxy/search returns.
        self.assertIn(
            "FROM proxy_traffic WHERE id = ?",
            db[db.index("private Map<String, Object> readCurlRow"):],
        )

        # The fallback follows traffic_meta.proxy_traffic_id, only when non-null.
        linked = db[db.index("private long linkedProxyTrafficId"):]
        linked = linked[: linked.index("\n    }\n")]
        self.assertIn("FROM traffic_meta", linked)
        self.assertIn("proxy_traffic_id IS NOT NULL", linked)

        route = ROUTE_HANDLER.read_text(encoding="utf-8")
        curl_route = route[route.index('app.get("/proxy/request/{id}/curl"'):]
        curl_route = curl_route[: curl_route.index("\n        });")]
        # Response exposes the resolved public id and how it was reached.
        self.assertIn('response.put("resolved_via"', curl_route)
        self.assertIn('response.put("requested_id"', curl_route)
        # The 404 is specific about the id space, not a bare "Not found".
        self.assertIn("proxy_traffic id space", curl_route)
        self.assertIn("GET /proxy/search", curl_route)

    def test_build_targets_openjdk_21(self):
        pom = (TOOL_ROOT / "pom.xml").read_text(encoding="utf-8")

        self.assertIn("<maven.compiler.source>21</maven.compiler.source>", pom)
        self.assertIn("<maven.compiler.target>21</maven.compiler.target>", pom)
        self.assertIn("<source>21</source>", pom)
        self.assertIn("<target>21</target>", pom)


if __name__ == "__main__":
    unittest.main()
