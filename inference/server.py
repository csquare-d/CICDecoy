# CI/CDecoy — LLM Inference Service
# inference/src/server.py
#
# Centralized inference gateway for all Tier 3 adaptive decoys.
# Decoy containers send commands + session context; this service
# constructs the prompt, runs inference, filters output, and returns
# a realistic terminal response.
#
# Runs as a single service on the k3s cluster, shared by all decoys.

import hashlib
import logging
import threading
import time
from collections import OrderedDict
from contextlib import asynccontextmanager

import os
import secrets

import httpx
from fastapi import Depends, FastAPI, HTTPException
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from metrics import (
    CACHE_SIZE,
    INFERENCE_LATENCY,
    INFERENCE_REQUESTS,
    INFERENCE_TOKENS,
)
from prometheus_client import make_asgi_app
from prompt_engine import PromptEngine
import re
from pydantic import BaseModel, Field, field_validator
from response_filter import ResponseFilter

logger = logging.getLogger("cicdecoy.inference")

_LABEL_RE = re.compile(r'[^a-zA-Z0-9._-]')


def _sanitize_label(value: str, max_len: int = 64) -> str:
    """Sanitize a value for use as a Prometheus metric label."""
    if not isinstance(value, str):
        value = str(value)
    value = _LABEL_RE.sub('_', value)
    return value[:max_len]

_bearer = HTTPBearer(auto_error=False)
INFERENCE_API_KEY = os.getenv("INFERENCE_API_KEY", "")


def _require_auth(creds: HTTPAuthorizationCredentials = Depends(_bearer)):
    """Validate Bearer token. Skipped if INFERENCE_API_KEY is empty (dev mode)."""
    if not INFERENCE_API_KEY:
        return  # No auth configured — development mode
    if not creds or not secrets.compare_digest(creds.credentials, INFERENCE_API_KEY):
        raise HTTPException(status_code=401, detail="Invalid or missing Bearer token")


# ─────────────────────────────────────────────────────────
#  Request / Response Models
# ─────────────────────────────────────────────────────────

class SessionContext(BaseModel):
    hostname: str = Field(..., max_length=256)
    username: str = Field(..., max_length=256)
    uid: int
    cwd: str = Field(..., max_length=4096)
    env: dict = {}
    command_history: list[str] = Field(default=[], max_length=100)
    filesystem_snapshot: dict = {}

    @field_validator("env")
    @classmethod
    def validate_env(cls, v):
        if len(v) > 256:
            raise ValueError(f"env dict exceeds 256 keys (got {len(v)})")
        for key, value in v.items():
            if not isinstance(key, str) or len(key) > 256:
                raise ValueError("env key must be a string of at most 256 chars")
            if not isinstance(value, str) or len(value) > 8192:
                raise ValueError("env value must be a string of at most 8192 chars")
        return v

    @field_validator("filesystem_snapshot")
    @classmethod
    def validate_filesystem_snapshot(cls, v):
        if len(v) > 5000:
            raise ValueError(f"filesystem_snapshot dict exceeds 5000 keys (got {len(v)})")
        for key, value in v.items():
            if not isinstance(key, str) or len(key) > 512:
                raise ValueError("filesystem_snapshot key must be a string of at most 512 chars")
            if not isinstance(value, str) or len(value) > 65536:
                raise ValueError("filesystem_snapshot value must be a string of at most 65536 chars")
        return v

    @field_validator("command_history")
    @classmethod
    def validate_command_history(cls, v):
        for i, cmd in enumerate(v):
            if not isinstance(cmd, str) or len(cmd) > 4096:
                raise ValueError(f"command_history[{i}] must be a string of at most 4096 chars")
        return v

class InferenceConfig(BaseModel):
    max_tokens: int = Field(default=4096, le=16384)
    temperature: float = Field(default=0.3, ge=0.0, le=2.0)

class CommandRequest(BaseModel):
    command: str = Field(..., max_length=65536)
    profile: str = Field(..., max_length=128)
    session_context: SessionContext
    config: InferenceConfig = InferenceConfig()

class CommandResponse(BaseModel):
    output: str
    cacheable: bool = False
    inference_time_ms: int = 0
    tokens_used: int = 0
    source: str = "llm"   # "llm" | "cache" | "fallback"


# ─────────────────────────────────────────────────────────
#  Response Cache
# ─────────────────────────────────────────────────────────

class ResponseCache:
    """
    LRU cache for deterministic command responses.

    Commands like `uname -a` always return the same thing for a given
    profile+hostname. Caching these avoids redundant inference and
    keeps latency consistent.

    Backed by OrderedDict for O(1) eviction and move-to-end on access.
    """

    def __init__(self, max_size: int = 10_000):
        self.max_size = max_size
        self.cache: OrderedDict[str, dict] = OrderedDict()
        self._lock = threading.Lock()
        self.hits = 0
        self.misses = 0

    def get(self, key: str) -> str | None:
        with self._lock:
            if key in self.cache:
                self.hits += 1
                self.cache.move_to_end(key)
                return self.cache[key]["output"]
            self.misses += 1
            return None

    def put(self, key: str, output: str):
        # Cap cached output size to prevent memory exhaustion
        if len(output) > 65_536:  # 64 KB max per cached entry
            return  # Don't cache oversized responses
        with self._lock:
            if key in self.cache:
                # Update existing entry, refresh recency
                self.cache[key] = {"output": output, "created": time.time()}
                self.cache.move_to_end(key)
                return
            # Insert new entry
            self.cache[key] = {"output": output, "created": time.time()}
            # Evict oldest if over capacity
            while len(self.cache) > self.max_size:
                self.cache.popitem(last=False)

    def make_key(self, profile: str, hostname: str, cwd: str, command: str) -> str:
        """Deterministic cache key from command context."""
        raw = f"{profile}\x00{hostname}\x00{cwd}\x00{command}"
        return hashlib.sha256(raw.encode()).hexdigest()

    def __len__(self):
        with self._lock:
            return len(self.cache)

    def clear(self):
        with self._lock:
            self.cache.clear()

    @property
    def stats(self) -> dict:
        with self._lock:
            total = self.hits + self.misses
            return {
                "size": len(self.cache),
                "hits": self.hits,
                "misses": self.misses,
                "hit_rate": self.hits / total if total > 0 else 0,
            }


# ─────────────────────────────────────────────────────────
#  LLM Backend Interface
# ─────────────────────────────────────────────────────────

class LLMBackend:
    """
    Interface to the actual LLM runtime.

    Supports multiple backends:
    - Ollama (local, default for k3s)
    - vLLM (higher throughput, GPU required)
    - OpenAI-compatible API (external, for testing)

    The backend is abstracted so the rest of the service doesn't
    care which model or runtime is in use.
    """

    def __init__(self, config: dict):
        self.backend_type = config.get("type", "ollama")
        self.base_url = config.get("url", "http://localhost:11434")
        self.model = config.get("model", "llama3.1:8b")
        self.client: httpx.AsyncClient | None = None

    async def initialize(self):
        self.client = httpx.AsyncClient(
            base_url=self.base_url,
            timeout=60.0,
        )
        logger.info(f"LLM backend initialized: {self.backend_type} "
                     f"model={self.model} url={self.base_url}")

    async def generate(
        self,
        system_prompt: str,
        user_prompt: str,
        temperature: float = 0.3,
        max_tokens: int = 2048,
    ) -> dict:
        """
        Run inference and return the generated text.

        Returns dict with 'text', 'tokens_used', 'latency_ms'.
        """
        if self.backend_type == "ollama":
            return await self._ollama_generate(
                system_prompt, user_prompt, temperature, max_tokens
            )
        elif self.backend_type == "vllm":
            return await self._openai_compatible_generate(
                system_prompt, user_prompt, temperature, max_tokens
            )
        elif self.backend_type == "openai":
            return await self._openai_compatible_generate(
                system_prompt, user_prompt, temperature, max_tokens
            )
        else:
            raise ValueError(f"Unknown backend type: {self.backend_type}")

    async def _ollama_generate(
        self, system: str, user: str, temperature: float, max_tokens: int
    ) -> dict:
        start = time.time()
        response = await self.client.post("/api/generate", json={
            "model": self.model,
            "system": system,
            "prompt": user,
            "stream": False,
            "options": {
                "temperature": temperature,
                "num_predict": max_tokens,
                "stop": ["\n$", "\n#", "\nuser@", "\nroot@"],
            },
        })
        response.raise_for_status()
        if len(response.content) > 1_048_576:  # 1 MB max
            logger.warning("LLM response too large (%d bytes), truncating", len(response.content))
            return None
        data = response.json()
        text = data.get("response", "")
        if not text.strip():
            logger.warning("Ollama returned empty response")
            return None
        return {
            "text": text,
            "tokens_used": data.get("eval_count", 0),
            "latency_ms": int((time.time() - start) * 1000),
        }

    async def _openai_compatible_generate(
        self, system: str, user: str, temperature: float, max_tokens: int
    ) -> dict:
        start = time.time()
        response = await self.client.post("/v1/chat/completions", json={
            "model": self.model,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            "temperature": temperature,
            "max_tokens": max_tokens,
            "stop": ["\n$", "\n#", "\nuser@", "\nroot@"],
        })
        response.raise_for_status()
        if len(response.content) > 1_048_576:  # 1 MB max
            logger.warning("LLM response too large (%d bytes), truncating", len(response.content))
            return None
        data = response.json()
        choices = data.get("choices")
        if not choices or not isinstance(choices, list) or len(choices) == 0:
            logger.warning("OpenAI backend returned no choices")
            return None
        choice = choices[0]
        text = choice.get("message", {}).get("content", "")
        if not text.strip():
            logger.warning("OpenAI backend returned empty content")
            return None
        return {
            "text": text,
            "tokens_used": data.get("usage", {}).get("total_tokens", 0),
            "latency_ms": int((time.time() - start) * 1000),
        }

    async def close(self):
        if self.client:
            await self.client.aclose()


# ─────────────────────────────────────────────────────────
#  Inference Service
# ─────────────────────────────────────────────────────────

class InferenceService:
    """
    Core inference orchestrator.

    Flow:
    1. Receive command + context from decoy
    2. Check response cache
    3. Build system prompt from profile
    4. Inject session context into user prompt
    5. Run LLM inference
    6. Filter response (guardrails)
    7. Optionally cache deterministic responses
    8. Return to decoy
    """

    # Commands that always produce the same output for a given profile.
    # Safe to cache aggressively.
    CACHEABLE_PATTERNS = [
        r"^uname\b",
        r"^cat /etc/(os-release|hostname|issue|passwd|group|shells)$",
        r"^lsb_release\b",
        r"^arch$",
        r"^nproc$",
        r"^getconf\b",
    ]

    def __init__(self):
        self.prompt_engine = PromptEngine()
        self.response_filter = ResponseFilter()
        self.cache = ResponseCache(max_size=10_000)
        self.llm: LLMBackend | None = None

        # Metrics
        self.request_count = 0
        self.total_inference_ms = 0
        self._stats_lock = threading.Lock()

    async def initialize(self, llm_config: dict):
        self.llm = LLMBackend(llm_config)
        await self.llm.initialize()
        await self.prompt_engine.load_profiles()
        logger.info("Inference service initialized")

    async def process_command(self, request: CommandRequest) -> CommandResponse:
        """Process a single command from a decoy."""
        with self._stats_lock:
            self.request_count += 1

        # ── Check cache ──
        cache_key = self.cache.make_key(
            request.profile,
            request.session_context.hostname,
            request.session_context.cwd,
            request.command,
        )

        cached = self.cache.get(cache_key)
        if cached is not None:
            INFERENCE_REQUESTS.labels(profile=_sanitize_label(request.profile), source="cache").inc()
            return CommandResponse(
                output=cached,
                cacheable=True,
                inference_time_ms=0,
                tokens_used=0,
                source="cache",
            )

        # ── Build prompts ──
        try:
            system_prompt = self.prompt_engine.build_system_prompt(
                profile_name=request.profile,
                hostname=request.session_context.hostname,
                username=request.session_context.username,
            )
            user_prompt = self.prompt_engine.build_user_prompt(
                command=request.command,
                session_context=request.session_context,
            )
        except Exception as e:
            logger.error("Prompt construction failed for profile '%s': %s", request.profile, e)
            return CommandResponse(
                output=f"-bash: {request.command.split()[0] if request.command.split() else 'unknown'}: command not found",
                cacheable=False,
                inference_time_ms=0,
                tokens_used=0,
                source="fallback",
            )

        # ── Run inference ──
        if self.llm is None:
            raise HTTPException(status_code=503, detail="LLM backend not initialized")
        try:
            result = await self.llm.generate(
                system_prompt=system_prompt,
                user_prompt=user_prompt,
                temperature=request.config.temperature,
                max_tokens=request.config.max_tokens,
            )
        except httpx.TimeoutException as e:
            logger.warning(f"LLM backend timeout: {e}")
            raise HTTPException(status_code=504, detail="Inference backend timeout") from e
        except httpx.HTTPError as e:
            logger.error(f"LLM backend error: {e}")
            raise HTTPException(status_code=503, detail="Inference backend unavailable") from e
        except (KeyError, TypeError, ValueError) as e:
            logger.error(f"LLM response parsing error: {e}", exc_info=True)
            raise HTTPException(status_code=502, detail="Invalid response from inference backend") from e
        except Exception as e:
            logger.error(f"Unexpected inference error: {e}", exc_info=True)
            raise HTTPException(status_code=500, detail="Internal inference error") from e

        if result is None or "text" not in result:
            cmd_word = request.command.split()[0] if request.command.split() else "unknown"
            return CommandResponse(
                output=f"-bash: {cmd_word}: command not found",
                source="fallback",
            )

        output = result.get("text", "")

        # ── Filter response ──
        output = self.response_filter.apply(output, request.profile)

        # ── Cache if deterministic ──
        cacheable = self._is_cacheable(request.command)
        if cacheable and output.strip():  # Only cache non-empty responses
            self.cache.put(cache_key, output)
            CACHE_SIZE.set(len(self.cache))

        # ── Track metrics ──
        inference_ms = result.get("latency_ms", 0)
        tokens = result.get("tokens_used", 0)
        with self._stats_lock:
            self.total_inference_ms += inference_ms
        _profile = _sanitize_label(request.profile)
        INFERENCE_REQUESTS.labels(profile=_profile, source="llm").inc()
        INFERENCE_LATENCY.labels(profile=_profile).observe(inference_ms / 1000)
        INFERENCE_TOKENS.labels(profile=_profile).inc(tokens)

        return CommandResponse(
            output=output,
            cacheable=cacheable,
            inference_time_ms=inference_ms,
            tokens_used=tokens,
            source="llm",
        )

    def _is_cacheable(self, command: str) -> bool:
        return any(re.match(p, command) for p in self.CACHEABLE_PATTERNS)

    @property
    def stats(self) -> dict:
        with self._stats_lock:
            return {
                "requests": self.request_count,
                "avg_inference_ms": (
                    self.total_inference_ms / self.request_count
                    if self.request_count > 0 else 0.0
                ),
                "cache": self.cache.stats,
            }


# ─────────────────────────────────────────────────────────
#  FastAPI Application
# ─────────────────────────────────────────────────────────

service = InferenceService()

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Load config from env / mounted configmap
    import os

    import yaml
    config_path = os.environ.get(
        "MODEL_CONFIG", "/etc/cicdecoy/model-config.yaml"
    )
    if os.path.exists(config_path):
        with open(config_path) as f:
            llm_config = yaml.safe_load(f) or {"type": "ollama", "model": "llama3.1:8b"}
    else:
        llm_config = {"type": "ollama", "model": "llama3.1:8b"}

    try:
        await service.initialize(llm_config)
    except Exception as e:
        logger.error(f"Failed to initialize inference service: {e}", exc_info=True)
        raise
    logger.info("Inference gateway ready")
    yield
    if service.llm:
        await service.llm.close()

app = FastAPI(
    title="CI/CDecoy Inference Gateway",
    version="0.1.0",
    lifespan=lifespan,
)

metrics_app = make_asgi_app()
app.mount("/metrics", metrics_app)


# Authentication: Set INFERENCE_API_KEY env var to require Bearer token auth.
# Rate limiting: For production, use a reverse proxy (nginx, envoy) with
# rate limiting configured in front of this service.


@app.post("/v1/command", response_model=CommandResponse, dependencies=[Depends(_require_auth)])
async def handle_command(request: CommandRequest):
    """
    Process a command from a Tier 3 decoy.

    The decoy sends the raw command + full session context.
    We return the terminal output the attacker should see.
    """
    return await service.process_command(request)


@app.get("/healthz")
async def liveness():
    """Kubernetes liveness probe — no auth required."""
    return {"status": "ok"}


@app.get("/v1/health")
async def health():
    return {"status": "healthy"}


@app.get("/v1/cache/stats", dependencies=[Depends(_require_auth)])
async def cache_stats():
    return service.cache.stats


@app.post("/v1/cache/flush", dependencies=[Depends(_require_auth)])
async def flush_cache():
    service.cache.clear()
    return {"status": "flushed"}
