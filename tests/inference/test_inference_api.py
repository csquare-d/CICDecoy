"""
CI/CDecoy --- Inference API Tests

Tests for server.py: the FastAPI inference gateway. LLM backend calls
are mocked so tests run without Ollama/vLLM.
"""

import hashlib
import time
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from httpx import ASGITransport, AsyncClient

from server import (
    app,
    service,
    CommandRequest,
    CommandResponse,
    InferenceConfig,
    SessionContext,
    InferenceService,
    ResponseCache,
    LLMBackend,
)


# -- Helpers --------------------------------------------------------

def make_session_context(**overrides) -> dict:
    """Build a minimal SessionContext dict for API requests."""
    ctx = {
        "hostname": "web-prod-01",
        "username": "admin",
        "uid": 1000,
        "cwd": "/home/admin",
        "env": {"PATH": "/usr/bin", "HOME": "/home/admin"},
        "command_history": ["whoami", "id"],
        "filesystem_snapshot": {},
    }
    ctx.update(overrides)
    return ctx


def make_command_request(**overrides) -> dict:
    """Build a minimal CommandRequest dict for API requests."""
    req = {
        "command": "ls -la",
        "profile": "web-server",
        "session_context": make_session_context(),
    }
    req.update(overrides)
    return req


# -- Fixtures -------------------------------------------------------

@pytest.fixture(autouse=True)
def _reset_service():
    """Reset service state between tests."""
    service.cache = ResponseCache(max_size=50_000)
    service.request_count = 0
    service.total_inference_ms = 0
    yield


@pytest.fixture
def mock_llm():
    """Mock the LLM backend to return controlled responses."""
    backend = AsyncMock(spec=LLMBackend)
    backend.generate = AsyncMock(return_value={
        "text": "total 32\ndrwxr-xr-x 2 admin admin 4096 Jan 15 bin",
        "tokens_used": 42,
        "latency_ms": 150,
    })
    return backend


@pytest.fixture
def ready_service(mock_llm):
    """Service with mock LLM and loaded prompt engine."""
    service.llm = mock_llm
    service.prompt_engine.profiles = {
        "web-server": {
            "system": {"os": "Ubuntu 22.04 LTS"},
            "users": [],
            "software": {},
            "environment": {},
            "narrative": "A web server.",
        }
    }
    return service


@pytest.fixture
def client(ready_service):
    """HTTPX async client bypassing lifespan."""
    transport = ASGITransport(app=app)
    return AsyncClient(transport=transport, base_url="http://test")


# ===================================================================
#  ResponseCache Unit Tests
# ===================================================================

class TestResponseCache:

    def test_cache_miss_returns_none(self):
        cache = ResponseCache()
        assert cache.get("nonexistent") is None

    def test_cache_put_and_get(self):
        cache = ResponseCache()
        cache.put("key1", "output1")
        assert cache.get("key1") == "output1"

    def test_cache_hit_miss_counters(self):
        cache = ResponseCache()
        cache.put("k", "v")
        cache.get("k")
        cache.get("missing")
        assert cache.hits == 1
        assert cache.misses == 1

    def test_cache_lru_eviction(self):
        cache = ResponseCache(max_size=3)
        cache.put("a", "1")
        cache.put("b", "2")
        cache.put("c", "3")
        cache.put("d", "4")  # should evict "a"
        assert cache.get("a") is None
        assert cache.get("b") == "2"
        assert cache.get("d") == "4"

    def test_cache_lru_access_refreshes(self):
        cache = ResponseCache(max_size=3)
        cache.put("a", "1")
        cache.put("b", "2")
        cache.put("c", "3")
        cache.get("a")  # refresh "a"
        cache.put("d", "4")  # should evict "b" (oldest after refresh)
        assert cache.get("a") == "1"
        assert cache.get("b") is None

    def test_cache_make_key_deterministic(self):
        cache = ResponseCache()
        k1 = cache.make_key("web", "host", "/home", "ls")
        k2 = cache.make_key("web", "host", "/home", "ls")
        assert k1 == k2

    def test_cache_make_key_varies_with_input(self):
        cache = ResponseCache()
        k1 = cache.make_key("web", "host", "/home", "ls")
        k2 = cache.make_key("web", "host", "/home", "pwd")
        assert k1 != k2

    def test_cache_make_key_varies_with_profile(self):
        cache = ResponseCache()
        k1 = cache.make_key("web", "host", "/home", "ls")
        k2 = cache.make_key("db", "host", "/home", "ls")
        assert k1 != k2

    def test_cache_stats(self):
        cache = ResponseCache()
        cache.put("a", "1")
        cache.get("a")
        cache.get("b")
        stats = cache.stats
        assert stats["size"] == 1
        assert stats["hits"] == 1
        assert stats["misses"] == 1
        assert stats["hit_rate"] == 0.5

    def test_cache_stats_no_requests(self):
        cache = ResponseCache()
        stats = cache.stats
        assert stats["hit_rate"] == 0


# ===================================================================
#  InferenceService Unit Tests
# ===================================================================

class TestInferenceService:

    @pytest.mark.asyncio
    async def test_process_command_returns_response(self, ready_service):
        request = CommandRequest(**make_command_request())
        response = await ready_service.process_command(request)
        assert isinstance(response, CommandResponse)
        assert response.source == "llm"
        assert response.tokens_used == 42
        assert response.inference_time_ms == 150

    @pytest.mark.asyncio
    async def test_process_command_calls_llm(self, ready_service, mock_llm):
        request = CommandRequest(**make_command_request(command="whoami"))
        await ready_service.process_command(request)
        mock_llm.generate.assert_called_once()

    @pytest.mark.asyncio
    async def test_process_command_applies_filter(self, ready_service, mock_llm):
        """Response filter should strip LLM formatting artifacts."""
        mock_llm.generate.return_value = {
            "text": "```\nhello world\n```",
            "tokens_used": 10,
            "latency_ms": 50,
        }
        request = CommandRequest(**make_command_request())
        response = await ready_service.process_command(request)
        assert "```" not in response.output
        assert "hello world" in response.output

    @pytest.mark.asyncio
    async def test_process_command_filters_character_break(self, ready_service, mock_llm):
        """If LLM breaks character, filter should catch it."""
        mock_llm.generate.return_value = {
            "text": "I'm an AI and can't actually run commands.",
            "tokens_used": 15,
            "latency_ms": 100,
        }
        request = CommandRequest(**make_command_request())
        response = await ready_service.process_command(request)
        assert "AI" not in response.output

    @pytest.mark.asyncio
    async def test_process_command_caches_deterministic(self, ready_service, mock_llm):
        """Deterministic commands like uname should be cached."""
        request = CommandRequest(**make_command_request(command="uname -a"))
        resp1 = await ready_service.process_command(request)
        assert resp1.cacheable is True
        assert resp1.source == "llm"

        resp2 = await ready_service.process_command(request)
        assert resp2.source == "cache"
        assert resp2.inference_time_ms == 0

        # LLM should only be called once
        assert mock_llm.generate.call_count == 1

    @pytest.mark.asyncio
    async def test_process_command_no_cache_for_dynamic(self, ready_service, mock_llm):
        """Non-deterministic commands should not be cached."""
        request = CommandRequest(**make_command_request(command="ps aux"))
        response = await ready_service.process_command(request)
        assert response.cacheable is False

    @pytest.mark.asyncio
    async def test_process_command_llm_failure_returns_503(self, ready_service, mock_llm):
        """LLM failure should return 503, not crash."""
        mock_llm.generate.side_effect = Exception("Connection refused")
        request = CommandRequest(**make_command_request())
        with pytest.raises(Exception) as exc_info:
            await ready_service.process_command(request)
        # HTTPException with 503
        assert exc_info.value.status_code == 503

    @pytest.mark.asyncio
    async def test_request_count_increments(self, ready_service):
        assert ready_service.request_count == 0
        request = CommandRequest(**make_command_request())
        await ready_service.process_command(request)
        assert ready_service.request_count == 1
        await ready_service.process_command(request)
        assert ready_service.request_count == 2

    @pytest.mark.asyncio
    async def test_stats_tracking(self, ready_service):
        request = CommandRequest(**make_command_request())
        await ready_service.process_command(request)
        stats = ready_service.stats
        assert stats["requests"] == 1
        assert stats["avg_inference_ms"] == 150

    def test_is_cacheable_uname(self, ready_service):
        assert ready_service._is_cacheable("uname -a") is True

    def test_is_cacheable_cat_os_release(self, ready_service):
        assert ready_service._is_cacheable("cat /etc/os-release") is True

    def test_is_cacheable_cat_passwd(self, ready_service):
        assert ready_service._is_cacheable("cat /etc/passwd") is True

    def test_is_cacheable_lsb_release(self, ready_service):
        assert ready_service._is_cacheable("lsb_release -a") is True

    def test_is_cacheable_arch(self, ready_service):
        assert ready_service._is_cacheable("arch") is True

    def test_is_cacheable_nproc(self, ready_service):
        assert ready_service._is_cacheable("nproc") is True

    def test_not_cacheable_ls(self, ready_service):
        assert ready_service._is_cacheable("ls -la") is False

    def test_not_cacheable_ps(self, ready_service):
        assert ready_service._is_cacheable("ps aux") is False

    def test_not_cacheable_date(self, ready_service):
        assert ready_service._is_cacheable("date") is False


# ===================================================================
#  FastAPI Endpoint Tests
# ===================================================================

class TestCommandEndpoint:

    @pytest.mark.asyncio
    async def test_post_command_success(self, client):
        resp = await client.post("/v1/command", json=make_command_request())
        assert resp.status_code == 200
        data = resp.json()
        assert "output" in data
        assert data["source"] == "llm"
        assert data["tokens_used"] == 42

    @pytest.mark.asyncio
    async def test_post_command_missing_fields(self, client):
        resp = await client.post("/v1/command", json={"command": "ls"})
        assert resp.status_code == 422  # Pydantic validation error

    @pytest.mark.asyncio
    async def test_post_command_empty_command(self, client):
        req = make_command_request(command="")
        resp = await client.post("/v1/command", json=req)
        assert resp.status_code == 200  # empty command is valid

    @pytest.mark.asyncio
    async def test_post_command_custom_config(self, client):
        req = make_command_request()
        req["config"] = {"max_tokens": 1024, "temperature": 0.7}
        resp = await client.post("/v1/command", json=req)
        assert resp.status_code == 200

    @pytest.mark.asyncio
    async def test_post_command_default_config(self, client):
        """Config should default to max_tokens=4096 temp=0.3."""
        req = make_command_request()
        # No config key -- should use defaults
        resp = await client.post("/v1/command", json=req)
        assert resp.status_code == 200


class TestHealthEndpoint:

    @pytest.mark.asyncio
    async def test_health_returns_200(self, client):
        resp = await client.get("/v1/health")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "healthy"

    @pytest.mark.asyncio
    async def test_health_includes_stats(self, client):
        resp = await client.get("/v1/health")
        data = resp.json()
        assert "stats" in data
        stats = data["stats"]
        assert "requests" in stats
        assert "cache" in stats
        assert "avg_inference_ms" in stats


class TestCacheEndpoints:

    @pytest.mark.asyncio
    async def test_cache_stats(self, client):
        resp = await client.get("/v1/cache/stats")
        assert resp.status_code == 200
        data = resp.json()
        assert "size" in data
        assert "hits" in data
        assert "misses" in data
        assert "hit_rate" in data

    @pytest.mark.asyncio
    async def test_flush_cache(self, client):
        # Prime the cache
        service.cache.put("test_key", "test_output")
        assert service.cache.get("test_key") == "test_output"

        resp = await client.post("/v1/cache/flush")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "flushed"

        # Cache should be empty now
        assert service.cache.get("test_key") is None

    @pytest.mark.asyncio
    async def test_flush_clears_access_order(self, client):
        service.cache.put("a", "1")
        service.cache.put("b", "2")
        await client.post("/v1/cache/flush")
        assert len(service.cache.access_order) == 0
        assert len(service.cache.cache) == 0


# ===================================================================
#  LLMBackend Unit Tests
# ===================================================================

class TestLLMBackend:

    def test_default_config(self):
        backend = LLMBackend({})
        assert backend.backend_type == "ollama"
        assert backend.model == "llama3.1:8b"
        assert backend.base_url == "http://localhost:11434"

    def test_custom_config(self):
        backend = LLMBackend({
            "type": "vllm",
            "model": "mistral-7b",
            "url": "http://gpu-node:8000",
        })
        assert backend.backend_type == "vllm"
        assert backend.model == "mistral-7b"
        assert backend.base_url == "http://gpu-node:8000"

    @pytest.mark.asyncio
    async def test_unknown_backend_raises(self):
        backend = LLMBackend({"type": "unknown_backend"})
        await backend.initialize()
        with pytest.raises(ValueError, match="Unknown backend type"):
            await backend.generate("system", "user")

    @pytest.mark.asyncio
    async def test_initialize_creates_client(self):
        backend = LLMBackend({})
        assert backend.client is None
        await backend.initialize()
        assert backend.client is not None
        await backend.close()

    @pytest.mark.asyncio
    async def test_close_without_initialize(self):
        backend = LLMBackend({})
        await backend.close()  # should not raise


# ===================================================================
#  Pydantic Model Validation
# ===================================================================

class TestRequestModels:

    def test_session_context_defaults(self):
        ctx = SessionContext(
            hostname="h", username="u", uid=0, cwd="/"
        )
        assert ctx.env == {}
        assert ctx.command_history == []
        assert ctx.filesystem_snapshot == {}

    def test_inference_config_defaults(self):
        cfg = InferenceConfig()
        assert cfg.max_tokens == 4096
        assert cfg.temperature == 0.3

    def test_command_request_default_config(self):
        req = CommandRequest(
            command="ls",
            profile="web",
            session_context=SessionContext(
                hostname="h", username="u", uid=0, cwd="/"
            ),
        )
        assert req.config.max_tokens == 4096
        assert req.config.temperature == 0.3

    def test_command_response_defaults(self):
        resp = CommandResponse(output="hello")
        assert resp.cacheable is False
        assert resp.source == "llm"
        assert resp.inference_time_ms == 0
        assert resp.tokens_used == 0
