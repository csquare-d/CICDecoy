# CI/CDecoy — Makefile
#
# No API keys needed. Everything runs locally.

.PHONY: help up up-tier3 down build test ssh ssh3 logs events db clean capture-responses dashboard

COMPOSE = docker compose -f docker-compose.dev.yaml

help: ## Show this help
	@echo ""
	@echo "  CI/CDecoy — Local Development"
	@echo "  No API keys required. Everything runs offline."
	@echo ""
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2}'
	@echo ""

# ── Stack Management ─────────────────────────────────

up: ## Start Tier 2 HiFi stack (no LLM, no API key)
	$(COMPOSE) up --build -d
	@echo ""
	@echo "  CI/CDecoy is running! (Tier 2 High-Fidelity)"
	@echo ""
	@echo "  SSH decoy:     ssh admin@localhost -p 2222"
	@echo "  Password:      admin123"
	@echo "  Dashboard:     http://localhost:8080"
	@echo "  NATS monitor:  http://localhost:8222"
	@echo ""

up-tier3: ## Start with local LLM (Ollama, ~2GB download first time)
	$(COMPOSE) --profile tier3 up --build -d
	@echo ""
	@echo "  CI/CDecoy is running! (Tier 2 + Tier 3)"
	@echo ""
	@echo "  Tier 2 decoy:  ssh admin@localhost -p 2222"
	@echo "  Tier 3 decoy:  ssh admin@localhost -p 2223  (LLM-backed)"
	@echo "  Password:      admin123"
	@echo "  Dashboard:     http://localhost:8080"
	@echo "  Ollama:        http://localhost:11434"
	@echo "  Inference:     http://localhost:8000/v1/health"
	@echo ""

down: ## Stop everything
	$(COMPOSE) --profile tier3 --profile debug down

build: ## Build all images without starting
	$(COMPOSE) --profile tier3 build

# ── Connect to Decoys ────────────────────────────────

ssh: ## SSH into the Tier 2 decoy
	@ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
		admin@localhost -p 2222

ssh3: ## SSH into the Tier 3 decoy (requires up-tier3)
	@ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
		admin@localhost -p 2223

# ── Dashboard ────────────────────────────────────────

dashboard: ## Open the dashboard in your browser
	@echo "  Dashboard: http://localhost:8080"
	@which xdg-open >/dev/null 2>&1 && xdg-open http://localhost:8080 || \
	 which open >/dev/null 2>&1 && open http://localhost:8080 || \
	 echo "  Open http://localhost:8080 in your browser"

dashboard-logs: ## Tail dashboard logs
	$(COMPOSE) logs -f dashboard

dashboard-inject: ## Inject a test event via the dashboard API
	@curl -s -X POST http://localhost:8080/api/test/inject | python3 -m json.tool

dashboard-burst: ## Inject 20 test events rapidly
	@for i in $$(seq 1 20); do \
		curl -s -X POST http://localhost:8080/api/test/inject > /dev/null & \
	done; \
	wait; \
	echo "  20 test events injected"

# ── Testing ──────────────────────────────────────────

test: ## Run unit tests
	cd ssh-decoy && python -m pytest ../tests/ -v --tb=short 2>/dev/null || \
		echo "Install test deps: pip install -r tests/requirements.txt"

# ── Observability ────────────────────────────────────

logs: ## Tail all container logs
	$(COMPOSE) --profile tier3 logs -f

logs-decoy: ## Tail SSH decoy logs
	$(COMPOSE) logs -f ssh-decoy

logs-collector: ## Tail CTI collector logs
	$(COMPOSE) logs -f cti-collector

logs-tier3: ## Tail Tier 3 decoy + inference logs
	$(COMPOSE) --profile tier3 logs -f ssh-decoy-tier3 inference ollama

events: ## Watch NATS events live
	$(COMPOSE) --profile debug run --rm nats-cli \
		nats sub "cicdecoy.>" -s nats://nats:4222

# ── Database ─────────────────────────────────────────

db: ## Open psql shell
	$(COMPOSE) exec timescaledb psql -U cicdecoy -d cicdecoy

db-events: ## Show last 20 events
	@$(COMPOSE) exec timescaledb psql -U cicdecoy -d cicdecoy -c \
		"SELECT to_char(timestamp, 'HH24:MI:SS') as time, \
		 decoy_name, event_type, source_ip, \
		 LEFT(raw_data->>'command', 50) as command \
		 FROM decoy_events ORDER BY timestamp DESC LIMIT 20;"

db-sessions: ## Show session summaries
	@$(COMPOSE) exec timescaledb psql -U cicdecoy -d cicdecoy -c \
		"SELECT LEFT(session_id, 8) as session, decoy_name, \
		 COUNT(*) as events, \
		 to_char(MIN(timestamp), 'HH24:MI:SS') as started, \
		 to_char(MAX(timestamp), 'HH24:MI:SS') as last \
		 FROM decoy_events \
		 WHERE session_id != '' AND session_id != 'system' \
		 AND session_id != 'pre-auth' \
		 GROUP BY session_id, decoy_name \
		 ORDER BY MAX(timestamp) DESC LIMIT 10;"

db-alerts: ## Show high-severity alerts
	@$(COMPOSE) exec timescaledb psql -U cicdecoy -d cicdecoy -c \
		"SELECT to_char(timestamp, 'HH24:MI:SS') as time, \
		 decoy_name, raw_data->>'severity' as severity, \
		 raw_data->>'behavior' as behavior, \
		 LEFT(raw_data->>'command', 60) as command \
		 FROM decoy_events WHERE event_type = 'alert' \
		 ORDER BY timestamp DESC LIMIT 20;"

db-falco: ## Show Falco runtime security alerts
	@$(COMPOSE) exec timescaledb psql -U cicdecoy -d cicdecoy -c \
		"SELECT to_char(timestamp, 'HH24:MI:SS') as time, \
		 rule_name, priority, pod_name, \
		 LEFT(command_line, 50) as command, \
		 LEFT(correlated_session_id, 8) as session \
		 FROM falco_alerts ORDER BY timestamp DESC LIMIT 20;"

db-engage: ## Show Engage effectiveness summary
	@$(COMPOSE) exec timescaledb psql -U cicdecoy -d cicdecoy -c \
		"SELECT intelligence_value, COUNT(*) as sessions, \
		 ROUND(AVG(engagement_duration)::numeric, 0) as avg_duration_s, \
		 SUM(ttps_observed) as total_ttps, \
		 SUM(CASE WHEN deception_maintained THEN 1 ELSE 0 END) as deception_held, \
		 SUM(CASE WHEN escape_attempted THEN 1 ELSE 0 END) as escapes \
		 FROM engage_outcomes GROUP BY intelligence_value \
		 ORDER BY CASE intelligence_value \
		   WHEN 'critical' THEN 1 WHEN 'high' THEN 2 \
		   WHEN 'medium' THEN 3 ELSE 4 END;"

db-escapes: ## Show sessions where attacker detected the honeypot
	@$(COMPOSE) exec timescaledb psql -U cicdecoy -d cicdecoy -c \
		"SELECT LEFT(e.session_id, 8) as session, e.decoy_name, \
		 e.commands_captured as cmds, \
		 ROUND(e.engagement_duration::numeric, 0) as duration_s, \
		 f.rule_name as escape_method, \
		 LEFT(f.command_line, 40) as escape_cmd \
		 FROM engage_outcomes e \
		 JOIN falco_alerts f ON f.correlated_session_id = e.session_id \
		 WHERE e.escape_attempted = TRUE \
		 ORDER BY e.timestamp DESC LIMIT 10;"

# ── Response Database ────────────────────────────────

capture-responses: ## Capture responses from localhost for response DB
	python tools/capture_responses.py \
		--local \
		--profile dev-workstation \
		--output responses/localhost-capture.json
	@echo "Response database saved to responses/localhost-capture.json"

# ── Cleanup ──────────────────────────────────────────

clean: ## Remove all data volumes
	$(COMPOSE) --profile tier3 --profile debug down -v
	@echo "All volumes removed"

reset: ## Full reset — remove volumes, rebuild images
	$(COMPOSE) --profile tier3 --profile debug down -v --rmi local
	@echo "Clean slate"