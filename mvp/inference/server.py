# CI/CDecoy — LLM Inference Service
# inference/src/server.py
#
# Centralized inference gateway for all Tier 3 adaptive decoys.
# Decoy containers send commands + session context; this service
# constructs the prompt, runs inference, filters output, and returns
# a realistic terminal response.
#
# Runs as a single service on the k3s cluster, shared by all decoys.

import asyncio
import hashlib
import json
import logging
import time
from contextlib import asynccontextmanager
from typing import Optional

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import httpx

from prompt_engine import PromptEngine
from response_filter import ResponseFilter
from timing import TimingModel

logger = logging.getLogger("cicdecoy.inference")


# ─────────────────────────────────────────────────────────
#  Request / Response Models
# ─────────────────────────────────────────────────────────

class SessionContext(BaseModel):
    hostname: str
    username: str
    uid: int
    cwd: str
    env: dict = {}
    command_history: list[str] = []
    filesystem_snapshot: dict = {}

class InferenceConfig(BaseModel):
    max_tokens: int = 4096
    temperature: float = 0.3

class CommandRequest(BaseModel):
    command: str
    profile: str
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
    """

    def __init__(self, max_size: int = 10_000):
        self.max_size = max_size
        self.cache: dict[str, dict] = {}
        self.access_order: list[str] = []
        self.hits = 0
        self.misses = 0

    def get(self, key: str) -> Optional[str]:
        if key in self.cache:
            self.hits += 1
            # Move to end (most recent)
            self.access_order.remove(key)
            self.access_order.append(key)
            return self.cache[key]["output"]
        self.misses += 1
        return None

    def put(self, key: str, output: str):
        if len(self.cache) >= self.max_size:
            # Evict least recently used
            oldest = self.access_order.pop(0)
            del self.cache[oldest]

        self.cache[key] = {"output": output, "created": time.time()}
        self.access_order.append(key)

    def make_key(self, profile: str, hostname: str, cwd: str, command: str) -> str:
        """Deterministic cache key from command context."""
        raw = f"{profile}:{hostname}:{cwd}:{command}"
        return hashlib.sha256(raw.encode()).hexdigest()[:16]

    @property
    def stats(self) -> dict:
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
        self.client: Optional[httpx.AsyncClient] = None

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
        start = time.time()

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
        data = response.json()
        return {
            "text": data.get("response", ""),
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
        data = response.json()
        choice = data["choices"][0]
        return {
            "text": choice["message"]["content"],
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
        self.timing_model = TimingModel()
        self.cache = ResponseCache(max_size=50_000)
        self.llm: Optional[LLMBackend] = None

        # Metrics
        self.request_count = 0
        self.total_inference_ms = 0

    async def initialize(self, llm_config: dict):
        self.llm = LLMBackend(llm_config)
        await self.llm.initialize()
        await self.prompt_engine.load_profiles()
        logger.info("Inference service initialized")

    async def process_command(self, request: CommandRequest) -> CommandResponse:
        """Process a single command from a decoy."""
        self.request_count += 1
        start = time.time()

        # ── Check cache ──
        cache_key = self.cache.make_key(
            request.profile,
            request.session_context.hostname,
            request.session_context.cwd,
            request.command,
        )

        cached = self.cache.get(cache_key)
        if cached is not None:
            return CommandResponse(
                output=cached,
                cacheable=True,
                inference_time_ms=0,
                tokens_used=0,
                source="cache",
            )

        # ── Build prompts ──
        system_prompt = self.prompt_engine.build_system_prompt(
            profile_name=request.profile,
            hostname=request.session_context.hostname,
            username=request.session_context.username,
        )

        user_prompt = self.prompt_engine.build_user_prompt(
            command=request.command,
            session_context=request.session_context,
        )

        # ── Run inference ──
        try:
            result = await self.llm.generate(
                system_prompt=system_prompt,
                user_prompt=user_prompt,
                temperature=request.config.temperature,
                max_tokens=request.config.max_tokens,
            )
        except Exception as e:
            logger.error(f"LLM inference failed: {e}")
            raise HTTPException(status_code=503, detail="Inference unavailable")

        output = result["text"]

        # ── Filter response ──
        output = self.response_filter.apply(output, request.profile)

        # ── Cache if deterministic ──
        cacheable = self._is_cacheable(request.command)
        if cacheable:
            self.cache.put(cache_key, output)

        # ── Track metrics ──
        inference_ms = result["latency_ms"]
        self.total_inference_ms += inference_ms

        return CommandResponse(
            output=output,
            cacheable=cacheable,
            inference_time_ms=inference_ms,
            tokens_used=result["tokens_used"],
            source="llm",
        )

    def _is_cacheable(self, command: str) -> bool:
        import re
        return any(re.match(p, command) for p in self.CACHEABLE_PATTERNS)

    @property
    def stats(self) -> dict:
        return {
            "requests": self.request_count,
            "avg_inference_ms": (
                self.total_inference_ms / self.request_count
                if self.request_count > 0 else 0
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
    import yaml, os
    config_path = os.environ.get(
        "MODEL_CONFIG", "/etc/cicdecoy/model-config.yaml"
    )
    if os.path.exists(config_path):
        with open(config_path) as f:
            llm_config = yaml.safe_load(f)
    else:
        llm_config = {"type": "ollama", "model": "llama3.1:8b"}

    await service.initialize(llm_config)
    logger.info("Inference gateway ready")
    yield
    if service.llm:
        await service.llm.close()

app = FastAPI(
    title="CI/CDecoy Inference Gateway",
    version="0.1.0",
    lifespan=lifespan,
)


@app.post("/v1/command", response_model=CommandResponse)
async def handle_command(request: CommandRequest):
    """
    Process a command from a Tier 3 decoy.

    The decoy sends the raw command + full session context.
    We return the terminal output the attacker should see.
    """
    return await service.process_command(request)


@app.get("/v1/health")
async def health():
    return {"status": "healthy", "stats": service.stats}


@app.get("/v1/cache/stats")
async def cache_stats():
    return service.cache.stats


@app.post("/v1/cache/flush")
async def flush_cache():
    service.cache.cache.clear()
    service.cache.access_order.clear()
    return {"status": "flushed"}
