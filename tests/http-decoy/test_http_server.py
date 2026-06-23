"""
CI/CDecoy -- HTTP Decoy Server Tests

Tests for login portal rendering, credential capture, API endpoints,
discovery routes, and server headers.
"""

import re

import pytest


def _extract_csrf(html: str) -> str:
    """Extract the CSRF token from a hidden form field in HTML."""
    match = re.search(r'name="_csrf"\s+value="([^"]+)"', html)
    assert match, "CSRF token not found in response HTML"
    return match.group(1)

# =========================================================================
#  Login Portal Tests -- AWS
# =========================================================================


class TestAWSLogin:
    @pytest.mark.asyncio
    async def test_aws_login_page_renders(self, client):
        resp = await client.get("/aws/signin")
        assert resp.status_code == 200
        assert "text/html" in resp.headers["content-type"]
        assert "Sign In" in resp.text or "Sign in" in resp.text

    @pytest.mark.asyncio
    async def test_aws_console_login_alias(self, client):
        resp = await client.get("/console/login")
        assert resp.status_code == 200
        assert "text/html" in resp.headers["content-type"]

    @pytest.mark.asyncio
    async def test_aws_login_captures_credentials(self, client, app):
        get_resp = await client.get("/aws/signin")
        csrf = _extract_csrf(get_resp.text)
        resp = await client.post(
            "/aws/signin",
            data={"email": "admin@corp.com", "password": "P@ssw0rd", "_csrf": csrf},
            follow_redirects=False,
        )
        assert resp.status_code == 303
        # Verify auth.attempt event was emitted
        app.state.emitter.emit.assert_called()
        calls = app.state.emitter.emit.call_args_list
        auth_calls = [c for c in calls if c.kwargs.get("event_type") == "auth.attempt"
                      or (c.args and c.args[0] == "auth.attempt")]
        assert len(auth_calls) >= 1

    @pytest.mark.asyncio
    async def test_aws_login_shows_error_on_redirect(self, client):
        resp = await client.get("/aws/signin?error=1")
        assert resp.status_code == 200
        assert "incorrect" in resp.text.lower() or "try again" in resp.text.lower()


# =========================================================================
#  Login Portal Tests -- GitLab
# =========================================================================


class TestGitLabLogin:
    @pytest.mark.asyncio
    async def test_gitlab_login_page_renders(self, client):
        resp = await client.get("/users/sign_in")
        assert resp.status_code == 200
        assert "text/html" in resp.headers["content-type"]
        assert "GitLab" in resp.text

    @pytest.mark.asyncio
    async def test_gitlab_login_alias(self, client):
        resp = await client.get("/gitlab/login")
        assert resp.status_code == 200

    @pytest.mark.asyncio
    async def test_gitlab_login_captures_credentials(self, client, app):
        get_resp = await client.get("/users/sign_in")
        csrf = _extract_csrf(get_resp.text)
        resp = await client.post(
            "/users/sign_in",
            data={"user[login]": "root", "user[password]": "admin123", "_csrf": csrf},
            follow_redirects=False,
        )
        assert resp.status_code == 303
        app.state.emitter.emit.assert_called()

    @pytest.mark.asyncio
    async def test_gitlab_login_shows_error(self, client):
        resp = await client.get("/users/sign_in?error=1")
        assert resp.status_code == 200
        assert "Invalid" in resp.text or "invalid" in resp.text


# =========================================================================
#  Login Portal Tests -- Jenkins
# =========================================================================


class TestJenkinsLogin:
    @pytest.mark.asyncio
    async def test_jenkins_login_page_renders(self, client):
        resp = await client.get("/login")
        assert resp.status_code == 200
        assert "text/html" in resp.headers["content-type"]
        assert "Jenkins" in resp.text

    @pytest.mark.asyncio
    async def test_jenkins_login_captures_credentials(self, client, app):
        get_resp = await client.get("/login")
        csrf = _extract_csrf(get_resp.text)
        resp = await client.post(
            "/j_spring_security_check",
            data={"j_username": "admin", "j_password": "jenkins", "_csrf": csrf},
            follow_redirects=False,
        )
        assert resp.status_code == 303
        app.state.emitter.emit.assert_called()

    @pytest.mark.asyncio
    async def test_jenkins_login_shows_error(self, client):
        resp = await client.get("/login?error=1")
        assert resp.status_code == 200
        assert "Invalid" in resp.text or "invalid" in resp.text


# =========================================================================
#  Login Portal Tests -- WordPress
# =========================================================================


class TestWordPressLogin:
    @pytest.mark.asyncio
    async def test_wp_login_page_renders(self, client):
        resp = await client.get("/wp-login.php")
        assert resp.status_code == 200
        assert "text/html" in resp.headers["content-type"]
        assert "WordPress" in resp.text

    @pytest.mark.asyncio
    async def test_wp_login_captures_credentials(self, client, app):
        get_resp = await client.get("/wp-login.php")
        csrf = _extract_csrf(get_resp.text)
        resp = await client.post(
            "/wp-login.php",
            data={"log": "admin", "pwd": "password123", "_csrf": csrf},
            follow_redirects=False,
        )
        assert resp.status_code == 303
        app.state.emitter.emit.assert_called()

    @pytest.mark.asyncio
    async def test_wp_admin_redirects_to_login(self, client):
        resp = await client.get("/wp-admin", follow_redirects=False)
        assert resp.status_code == 302
        assert "wp-login.php" in resp.headers["location"]

    @pytest.mark.asyncio
    async def test_wp_login_shows_error(self, client):
        resp = await client.get("/wp-login.php?error=1")
        assert resp.status_code == 200
        assert "ERROR" in resp.text or "Invalid" in resp.text


# =========================================================================
#  Login Portal Tests -- Corporate SSO
# =========================================================================


class TestCorporateLogin:
    @pytest.mark.asyncio
    async def test_corporate_login_page_renders(self, client):
        resp = await client.get("/sso/login")
        assert resp.status_code == 200
        assert "text/html" in resp.headers["content-type"]

    @pytest.mark.asyncio
    async def test_corporate_auth_login_alias(self, client):
        resp = await client.get("/auth/login")
        assert resp.status_code == 200

    @pytest.mark.asyncio
    async def test_corporate_root_serves_login(self, client):
        resp = await client.get("/")
        assert resp.status_code == 200
        assert "text/html" in resp.headers["content-type"]

    @pytest.mark.asyncio
    async def test_corporate_login_captures_credentials(self, client, app):
        get_resp = await client.get("/sso/login")
        csrf = _extract_csrf(get_resp.text)
        resp = await client.post(
            "/sso/login",
            data={"email": "user@acme.com", "password": "corp123", "_csrf": csrf},
            follow_redirects=False,
        )
        assert resp.status_code == 303
        app.state.emitter.emit.assert_called()

    @pytest.mark.asyncio
    async def test_corporate_login_shows_error(self, client):
        resp = await client.get("/sso/login?error=1")
        assert resp.status_code == 200
        assert "Invalid" in resp.text or "invalid" in resp.text or "try again" in resp.text.lower()


# =========================================================================
#  Login Portal Tests -- Outlook
# =========================================================================


class TestOutlookLogin:
    @pytest.mark.asyncio
    async def test_outlook_login_page_renders(self, client):
        resp = await client.get("/owa/")
        assert resp.status_code == 200
        assert "text/html" in resp.headers["content-type"]

    @pytest.mark.asyncio
    async def test_outlook_alias_renders(self, client):
        resp = await client.get("/outlook/")
        assert resp.status_code == 200

    @pytest.mark.asyncio
    async def test_mail_alias_renders(self, client):
        resp = await client.get("/mail/")
        assert resp.status_code == 200

    @pytest.mark.asyncio
    async def test_outlook_login_captures_credentials(self, client, app):
        get_resp = await client.get("/owa/")
        csrf = _extract_csrf(get_resp.text)
        resp = await client.post(
            "/owa/",
            data={"loginfmt": "user@company.com", "passwd": "outlook123", "_csrf": csrf},
            follow_redirects=False,
        )
        assert resp.status_code == 303
        app.state.emitter.emit.assert_called()

    @pytest.mark.asyncio
    async def test_outlook_login_shows_error(self, client):
        resp = await client.get("/owa/?error=1")
        assert resp.status_code == 200
        assert "incorrect" in resp.text.lower() or "password" in resp.text.lower()


# =========================================================================
#  Login Portal Tests -- phpMyAdmin
# =========================================================================


class TestPhpMyAdminLogin:
    @pytest.mark.asyncio
    async def test_phpmyadmin_login_page_renders(self, client):
        resp = await client.get("/phpmyadmin/")
        assert resp.status_code == 200
        assert "text/html" in resp.headers["content-type"]

    @pytest.mark.asyncio
    async def test_pma_alias_renders(self, client):
        resp = await client.get("/pma/")
        assert resp.status_code == 200

    @pytest.mark.asyncio
    async def test_phpmyadmin_login_captures_credentials(self, client, app):
        get_resp = await client.get("/phpmyadmin/")
        csrf = _extract_csrf(get_resp.text)
        resp = await client.post(
            "/phpmyadmin/",
            data={
                "pma_username": "root",
                "pma_password": "mysql123",
                "pma_serverchoice": "localhost",
                "_csrf": csrf,
            },
            follow_redirects=False,
        )
        assert resp.status_code == 303
        app.state.emitter.emit.assert_called()

    @pytest.mark.asyncio
    async def test_phpmyadmin_login_shows_error(self, client):
        resp = await client.get("/phpmyadmin/?error=1")
        assert resp.status_code == 200
        assert "denied" in resp.text.lower() or "Access" in resp.text


# =========================================================================
#  Login Portal Tests -- Grafana
# =========================================================================


class TestGrafanaLogin:
    @pytest.mark.asyncio
    async def test_grafana_login_page_renders(self, client):
        resp = await client.get("/grafana/login")
        assert resp.status_code == 200
        assert "text/html" in resp.headers["content-type"]

    @pytest.mark.asyncio
    async def test_monitoring_alias_renders(self, client):
        resp = await client.get("/monitoring/")
        assert resp.status_code == 200

    @pytest.mark.asyncio
    async def test_grafana_login_captures_credentials(self, client, app):
        get_resp = await client.get("/grafana/login")
        csrf = _extract_csrf(get_resp.text)
        resp = await client.post(
            "/grafana/login",
            data={"user": "admin", "password": "grafana", "_csrf": csrf},
            follow_redirects=False,
        )
        assert resp.status_code == 303
        app.state.emitter.emit.assert_called()


# =========================================================================
#  Login Portal Tests -- Generic Admin
# =========================================================================


class TestAdminLogin:
    @pytest.mark.asyncio
    async def test_admin_login_page_renders(self, client):
        resp = await client.get("/admin/")
        assert resp.status_code == 200
        assert "text/html" in resp.headers["content-type"]

    @pytest.mark.asyncio
    async def test_admin_login_alias(self, client):
        resp = await client.get("/admin/login")
        assert resp.status_code == 200

    @pytest.mark.asyncio
    async def test_administrator_alias(self, client):
        resp = await client.get("/administrator/")
        assert resp.status_code == 200

    @pytest.mark.asyncio
    async def test_admin_login_captures_credentials(self, client, app):
        get_resp = await client.get("/admin/")
        csrf = _extract_csrf(get_resp.text)
        resp = await client.post(
            "/admin/",
            data={"username": "admin", "password": "admin123", "_csrf": csrf},
            follow_redirects=False,
        )
        assert resp.status_code == 303
        app.state.emitter.emit.assert_called()


# =========================================================================
#  API Endpoint Tests
# =========================================================================


class TestAPIEndpoints:
    @pytest.mark.asyncio
    async def test_api_health(self, client):
        resp = await client.get("/api/v1/health")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "healthy"
        assert "version" in data
        assert "uptime" in data

    @pytest.mark.asyncio
    async def test_api_version(self, client):
        resp = await client.get("/api/v1/version")
        assert resp.status_code == 200
        data = resp.json()
        assert "version" in data
        assert "build" in data

    @pytest.mark.asyncio
    async def test_api_status(self, client):
        resp = await client.get("/api/v1/status")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "operational"
        assert "services" in data

    @pytest.mark.asyncio
    async def test_api_auth_login_returns_401(self, client):
        resp = await client.post(
            "/api/v1/auth/login",
            json={"username": "test", "password": "test"},
        )
        assert resp.status_code == 401
        data = resp.json()
        assert data["error"] == "invalid_credentials"

    @pytest.mark.asyncio
    async def test_api_auth_token_returns_401(self, client):
        resp = await client.post("/api/v1/auth/token", json={"grant_type": "password"})
        assert resp.status_code == 401

    @pytest.mark.asyncio
    async def test_api_auth_me_returns_401(self, client):
        resp = await client.get("/api/v1/auth/me")
        assert resp.status_code == 401
        assert resp.json()["error"] == "token_expired"

    @pytest.mark.asyncio
    async def test_api_users_returns_403(self, client):
        resp = await client.get("/api/v1/users")
        assert resp.status_code == 403
        assert resp.json()["error"] == "forbidden"

    @pytest.mark.asyncio
    async def test_api_users_detail_returns_403(self, client):
        resp = await client.get("/api/v1/users/123")
        assert resp.status_code == 403

    @pytest.mark.asyncio
    async def test_api_users_create_returns_403(self, client):
        resp = await client.post("/api/v1/users", json={"name": "evil"})
        assert resp.status_code == 403

    @pytest.mark.asyncio
    async def test_api_config_returns_403(self, client):
        resp = await client.get("/api/v1/config")
        assert resp.status_code == 403

    @pytest.mark.asyncio
    async def test_api_data_export_returns_403(self, client):
        resp = await client.get("/api/v1/data/export")
        assert resp.status_code == 403

    @pytest.mark.asyncio
    async def test_api_search_returns_empty_results(self, client):
        resp = await client.get("/api/v1/search?q=admin")
        assert resp.status_code == 200
        data = resp.json()
        assert data["results"] == []
        assert data["query"] == "admin"

    @pytest.mark.asyncio
    async def test_api_graphql_get(self, client):
        resp = await client.get("/api/v1/graphql")
        assert resp.status_code == 200
        data = resp.json()
        assert "errors" in data

    @pytest.mark.asyncio
    async def test_api_swagger_json(self, client):
        resp = await client.get("/api/v1/swagger.json")
        assert resp.status_code == 200
        data = resp.json()
        assert data["openapi"] == "3.0.3"

    @pytest.mark.asyncio
    async def test_api_catchall_returns_404(self, client):
        resp = await client.get("/api/nonexistent/path")
        assert resp.status_code == 404
        data = resp.json()
        assert data["error"] == "not_found"

    @pytest.mark.asyncio
    async def test_api_responses_have_security_headers(self, client):
        resp = await client.get("/api/v1/health")
        assert "x-content-type-options" in resp.headers
        assert "x-frame-options" in resp.headers
        assert resp.headers["server"] == "nginx/1.24.0"


# =========================================================================
#  Discovery Route Tests
# =========================================================================


class TestDiscoveryRoutes:
    @pytest.mark.asyncio
    async def test_robots_txt(self, client):
        resp = await client.get("/robots.txt")
        assert resp.status_code == 200
        assert "Disallow" in resp.text
        assert "/admin/" in resp.text

    @pytest.mark.asyncio
    async def test_sitemap_xml(self, client):
        resp = await client.get("/sitemap.xml")
        assert resp.status_code == 200
        assert "urlset" in resp.text

    @pytest.mark.asyncio
    async def test_security_txt(self, client):
        resp = await client.get("/.well-known/security.txt")
        assert resp.status_code == 200
        assert "Contact" in resp.text

    @pytest.mark.asyncio
    async def test_openid_configuration(self, client):
        resp = await client.get("/.well-known/openid-configuration")
        assert resp.status_code == 200
        data = resp.json()
        assert "authorization_endpoint" in data
        assert "token_endpoint" in data

    @pytest.mark.asyncio
    async def test_git_config_probe(self, client, app):
        resp = await client.get("/.git/config")
        assert resp.status_code == 403
        app.state.emitter.emit.assert_called()

    @pytest.mark.asyncio
    async def test_git_head_probe(self, client):
        resp = await client.get("/.git/HEAD")
        assert resp.status_code == 403

    @pytest.mark.asyncio
    async def test_svn_entries_probe(self, client):
        resp = await client.get("/.svn/entries")
        assert resp.status_code == 404

    @pytest.mark.asyncio
    async def test_backup_sql_probe(self, client):
        resp = await client.get("/backup.sql")
        assert resp.status_code == 403

    @pytest.mark.asyncio
    async def test_dot_env_returns_403_and_emits(self, client, app):
        resp = await client.get("/.env")
        assert resp.status_code == 403
        # Should emit a probe event
        app.state.emitter.emit.assert_called()

    @pytest.mark.asyncio
    async def test_wp_config_probe(self, client):
        resp = await client.get("/wp-config.php")
        assert resp.status_code == 403

    @pytest.mark.asyncio
    async def test_debug_probe(self, client):
        resp = await client.get("/debug/")
        assert resp.status_code == 403

    @pytest.mark.asyncio
    async def test_ds_store_probe(self, client):
        resp = await client.get("/.DS_Store")
        assert resp.status_code == 404


# =========================================================================
#  Server Header / Middleware Tests
# =========================================================================


class TestServerBehavior:
    @pytest.mark.asyncio
    async def test_server_header(self, client):
        resp = await client.get("/robots.txt")
        assert resp.headers.get("server") == "nginx/1.24.0"

    @pytest.mark.asyncio
    async def test_healthz_endpoint(self, client):
        resp = await client.get("/healthz")
        assert resp.status_code == 200
        assert resp.json()["status"] == "ok"

    @pytest.mark.asyncio
    async def test_catch_all_returns_nginx_404(self, client):
        resp = await client.get("/nonexistent/page/here")
        assert resp.status_code == 404
        assert "nginx" in resp.text.lower()

    @pytest.mark.asyncio
    async def test_session_cookie_set(self, client):
        resp = await client.get("/robots.txt")
        assert "_sess" in resp.headers.get("set-cookie", "")

    @pytest.mark.asyncio
    async def test_tomcat_manager_returns_401(self, client):
        resp = await client.get("/manager/html")
        assert resp.status_code == 401
        assert "WWW-Authenticate" in resp.headers

    @pytest.mark.asyncio
    async def test_actuator_health(self, client):
        resp = await client.get("/actuator/health")
        assert resp.status_code == 200
        assert resp.json()["status"] == "UP"

    @pytest.mark.asyncio
    async def test_actuator_env_returns_401(self, client):
        resp = await client.get("/actuator/env")
        assert resp.status_code == 401

    @pytest.mark.asyncio
    async def test_server_status_returns_403(self, client):
        resp = await client.get("/server-status")
        assert resp.status_code == 403


# =========================================================================
#  Request Size Limit Middleware Tests
# =========================================================================


class TestRequestSizeLimit:
    @pytest.mark.asyncio
    async def test_normal_sized_request_succeeds(self, client):
        """A request with Content-Length under MAX_REQUEST_BODY is allowed."""
        resp = await client.post(
            "/healthz",
            content=b"small body",
            headers={"content-length": "10"},
        )
        # The middleware must not block the request (no 413);
        # the endpoint itself may return 404 or 405 for POST, which is fine.
        assert resp.status_code != 413

    @pytest.mark.asyncio
    async def test_oversized_content_length_returns_413(self, client):
        """A request with Content-Length exceeding MAX_REQUEST_BODY is rejected."""
        oversized = str(1_048_576 + 1)  # 1 byte over the 1 MB limit
        resp = await client.post(
            "/healthz",
            content=b"",
            headers={"content-length": oversized},
        )
        assert resp.status_code == 413
        assert resp.json()["detail"] == "Request too large"

    @pytest.mark.asyncio
    async def test_request_without_content_length_is_allowed(self, client):
        """A request with no Content-Length header passes the middleware."""
        resp = await client.get("/healthz")
        assert resp.status_code == 200


# =========================================================================
#  CSRF Token Rejection Tests
# =========================================================================


class TestCSRFRejection:
    """Verify that POST requests without a valid CSRF token are rejected."""

    # -- AWS ---------------------------------------------------------------

    @pytest.mark.asyncio
    async def test_aws_login_rejects_missing_csrf(self, client):
        resp = await client.post(
            "/aws/signin",
            data={"email": "test@test.com", "password": "pass123"},
            follow_redirects=False,
        )
        assert resp.status_code == 303
        assert "error=csrf" in resp.headers.get("location", "")

    @pytest.mark.asyncio
    async def test_aws_login_rejects_invalid_csrf(self, client):
        resp = await client.post(
            "/aws/signin",
            data={"email": "test@test.com", "password": "pass123", "_csrf": "invalid_token"},
            follow_redirects=False,
        )
        assert resp.status_code == 303
        assert "error=csrf" in resp.headers.get("location", "")

    # -- GitLab ------------------------------------------------------------

    @pytest.mark.asyncio
    async def test_gitlab_login_rejects_missing_csrf(self, client):
        resp = await client.post(
            "/users/sign_in",
            data={"user[login]": "root", "user[password]": "admin123"},
            follow_redirects=False,
        )
        assert resp.status_code == 303
        assert "error=csrf" in resp.headers.get("location", "")

    @pytest.mark.asyncio
    async def test_gitlab_login_rejects_invalid_csrf(self, client):
        resp = await client.post(
            "/users/sign_in",
            data={"user[login]": "root", "user[password]": "admin123", "_csrf": "bogus"},
            follow_redirects=False,
        )
        assert resp.status_code == 303
        assert "error=csrf" in resp.headers.get("location", "")

    # -- Admin Panel -------------------------------------------------------

    @pytest.mark.asyncio
    async def test_admin_login_rejects_missing_csrf(self, client):
        resp = await client.post(
            "/admin/",
            data={"username": "admin", "password": "admin123"},
            follow_redirects=False,
        )
        assert resp.status_code == 303
        assert "error=csrf" in resp.headers.get("location", "")

    @pytest.mark.asyncio
    async def test_admin_login_rejects_invalid_csrf(self, client):
        resp = await client.post(
            "/admin/",
            data={"username": "admin", "password": "admin123", "_csrf": "forged_token"},
            follow_redirects=False,
        )
        assert resp.status_code == 303
        assert "error=csrf" in resp.headers.get("location", "")
