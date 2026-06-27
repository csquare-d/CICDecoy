.PHONY: help up up-tier3 down build test lint fmt check install ssh ssh3 logs events db clean \
       capture-responses dashboard dashboard-dev up-security falco-test falco-stats e2e-k3d \
       dashboard-inject dashboard-burst dashboard-logs logs-decoy logs-collector logs-tier3 \
       db-events db-sessions db-alerts db-falco db-engage db-escapes reset

COMPOSE := $(shell if docker compose version >/dev/null 2>&1; then echo "docker compose"; \
	elif command -v docker-compose >/dev/null 2>&1; then echo "docker-compose"; fi)

define require_compose
	@if [ -z "$(COMPOSE)" ]; then \
		echo "ERROR: No docker compose found."; \
		echo ""; \
		if [ "$$(uname)" = "Darwin" ]; then \
			echo "  brew install docker-compose"; \
			echo "  # or install Docker Desktop: https://docker.com/products/docker-desktop"; \
		elif [ "$$(uname)" = "Linux" ]; then \
			echo "  sudo apt install docker-compose-plugin  # Debian/Ubuntu"; \
			echo "  sudo dnf install docker-compose-plugin  # Fedora/RHEL"; \
		else \
			echo "  Install Docker Desktop: https://docker.com/products/docker-desktop"; \
		fi; \
		echo ""; \
		exit 1; \
	fi
endef

define require_cmd
	@command -v $(1) >/dev/null 2>&1 || { \
		echo "ERROR: $(1) not found."; \
		if [ "$$(uname)" = "Darwin" ]; then \
			echo "  brew install $(2)"; \
		elif [ "$$(uname)" = "Linux" ]; then \
			echo "  sudo apt install $(2)  # or equivalent for your distro"; \
		else \
			echo "  Install $(1): $(3)"; \
		fi; \
		exit 1; \
	}
endef

help: ## Show this help
	@echo ""
	@echo "  CI/CDecoy — Local Development"
	@echo ""
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2}'
	@echo ""

up: ## Start Tier 2 stack (no LLM, no API key)
	$(require_compose)
	$(COMPOSE) up --build -d
	@echo ""
	@echo "  SSH decoy:     ssh admin@localhost -p 2222  (password: admin123)"
	@echo "  HTTP decoy:    http://localhost:8888"
	@echo "  Dashboard:     http://localhost:8080"
	@echo "  NATS monitor:  http://localhost:8222"
	@echo ""

up-tier3: ## Start with local LLM (Ollama, ~2GB first time)
	$(require_compose)
	$(COMPOSE) --profile tier3 up --build -d
	@echo ""
	@echo "  Tier 2 SSH:    ssh admin@localhost -p 2222  (password: admin123)"
	@echo "  Tier 3 SSH:    ssh admin@localhost -p 2223  (LLM-backed)"
	@echo "  Dashboard:     http://localhost:8080"
	@echo ""

up-security: ## Start with Falco test pipeline
	$(require_compose)
	$(COMPOSE) --profile security up --build -d
	@echo ""
	@echo "  Falcosidekick: http://localhost:2801"
	@echo ""

down: ## Stop everything
	$(require_compose)
	$(COMPOSE) --profile tier3 --profile debug --profile security down

build: ## Build all images without starting
	$(require_compose)
	$(COMPOSE) --profile tier3 build

ssh: ## SSH into the Tier 2 decoy
	@ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null admin@localhost -p 2222

ssh3: ## SSH into the Tier 3 decoy
	@ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null admin@localhost -p 2223

dashboard: ## Open dashboard in browser
	@if command -v xdg-open >/dev/null 2>&1; then xdg-open http://localhost:8080; \
	elif command -v open >/dev/null 2>&1; then open http://localhost:8080; \
	elif command -v start >/dev/null 2>&1; then start http://localhost:8080; \
	else echo "Open http://localhost:8080 in your browser"; fi

dashboard-dev: ## Start frontend dev server (hot-reload)
	$(call require_cmd,node,node,https://nodejs.org)
	cd dashboard && npm install && npm run dev

dashboard-inject: ## Inject a test event
	@curl -sf -X POST http://localhost:8080/api/test/inject | python3 -m json.tool || \
		echo "ERROR: Dashboard not running or not reachable at localhost:8080"

dashboard-burst: ## Inject 20 test events
	@for i in $$(seq 1 20); do curl -sf -X POST http://localhost:8080/api/test/inject >/dev/null & done; \
		wait; echo "  20 test events injected"

dashboard-logs: ## Tail dashboard logs
	$(require_compose)
	$(COMPOSE) logs -f dashboard

install: ## Install Python dev dependencies
	$(call require_cmd,pip,python3-pip,https://pip.pypa.io)
	pip install ruff pre-commit
	pip install -r tests/requirements.txt
	pip install -r ssh-decoy/requirements.txt
	pip install -r cti/requirements.txt
	pip install -r inference/requirements.txt
	pip install -r dashboard/requirements.txt

lint: ## Run linter
	$(call require_cmd,ruff,ruff,https://docs.astral.sh/ruff)
	ruff check ssh-decoy/ cti/ dashboard/ inference/ http-decoy/ platform/operator/ tests/

fmt: ## Auto-format code
	$(call require_cmd,ruff,ruff,https://docs.astral.sh/ruff)
	ruff format ssh-decoy/ cti/ dashboard/ inference/ http-decoy/ platform/operator/ tests/
	ruff check --fix ssh-decoy/ cti/ dashboard/ inference/ http-decoy/ platform/operator/ tests/

test: ## Run unit tests
	$(call require_cmd,python3,python3,https://python.org)
	cd tests && python3 -m pytest -v --tb=short -o "addopts="

check: ## Lint + test
	@$(MAKE) lint
	@$(MAKE) test

logs: ## Tail all container logs
	$(require_compose)
	$(COMPOSE) logs -f

logs-decoy: ## Tail SSH decoy logs
	$(require_compose)
	$(COMPOSE) logs -f ssh-decoy

logs-collector: ## Tail CTI collector logs
	$(require_compose)
	$(COMPOSE) logs -f cti-collector

logs-tier3: ## Tail Tier 3 logs
	$(require_compose)
	$(COMPOSE) --profile tier3 logs -f ssh-decoy-tier3 inference ollama

events: ## Watch NATS events live
	$(require_compose)
	$(COMPOSE) --profile debug run --rm nats-cli nats sub "cicdecoy.>" -s nats://nats:4222

db: ## Open psql shell
	$(require_compose)
	$(COMPOSE) exec timescaledb psql -U cicdecoy -d cicdecoy

db-events: ## Show last 20 events
	$(require_compose)
	@$(COMPOSE) exec timescaledb psql -U cicdecoy -d cicdecoy -c \
		"SELECT to_char(timestamp, 'HH24:MI:SS') as time, \
		 decoy_name, event_type, source_ip, \
		 LEFT(raw_data->>'command', 50) as command \
		 FROM decoy_events ORDER BY timestamp DESC LIMIT 20;"

db-sessions: ## Show session summaries
	$(require_compose)
	@$(COMPOSE) exec timescaledb psql -U cicdecoy -d cicdecoy -c \
		"SELECT LEFT(session_id, 8) as session, decoy_name, \
		 COUNT(*) as events, \
		 to_char(MIN(timestamp), 'HH24:MI:SS') as started, \
		 to_char(MAX(timestamp), 'HH24:MI:SS') as last \
		 FROM decoy_events \
		 WHERE session_id != '' AND session_id != 'system' AND session_id != 'pre-auth' \
		 GROUP BY session_id, decoy_name \
		 ORDER BY MAX(timestamp) DESC LIMIT 10;"

db-alerts: ## Show high-severity alerts
	$(require_compose)
	@$(COMPOSE) exec timescaledb psql -U cicdecoy -d cicdecoy -c \
		"SELECT to_char(timestamp, 'HH24:MI:SS') as time, \
		 decoy_name, raw_data->>'severity' as severity, \
		 raw_data->>'behavior' as behavior, \
		 LEFT(raw_data->>'command', 60) as command \
		 FROM decoy_events WHERE event_type = 'alert' \
		 ORDER BY timestamp DESC LIMIT 20;"

db-falco: ## Show Falco alerts
	$(require_compose)
	@$(COMPOSE) exec timescaledb psql -U cicdecoy -d cicdecoy -c \
		"SELECT to_char(timestamp, 'HH24:MI:SS') as time, \
		 rule_name, priority, pod_name, \
		 LEFT(command_line, 50) as command \
		 FROM falco_alerts ORDER BY timestamp DESC LIMIT 20;"

db-engage: ## Show Engage effectiveness
	$(require_compose)
	@$(COMPOSE) exec timescaledb psql -U cicdecoy -d cicdecoy -c \
		"SELECT intelligence_value, COUNT(*) as sessions, \
		 ROUND(AVG(engagement_duration)::numeric, 0) as avg_duration_s, \
		 SUM(ttps_observed) as total_ttps \
		 FROM engage_outcomes GROUP BY intelligence_value \
		 ORDER BY CASE intelligence_value \
		   WHEN 'critical' THEN 1 WHEN 'high' THEN 2 \
		   WHEN 'medium' THEN 3 ELSE 4 END;"

db-escapes: ## Show honeypot detection attempts
	$(require_compose)
	@$(COMPOSE) exec timescaledb psql -U cicdecoy -d cicdecoy -c \
		"SELECT LEFT(e.session_id, 8) as session, e.decoy_name, \
		 e.commands_captured as cmds, \
		 ROUND(e.engagement_duration::numeric, 0) as duration_s, \
		 f.rule_name as escape_method \
		 FROM engage_outcomes e \
		 JOIN falco_alerts f ON f.correlated_session_id = e.session_id \
		 WHERE e.escape_attempted = TRUE \
		 ORDER BY e.timestamp DESC LIMIT 10;"

capture-responses: ## Capture responses for response DB
	$(call require_cmd,python3,python3,https://python.org)
	python3 tools/capture_responses.py --local --profile dev-workstation \
		--output decoys/responses/localhost-capture.json

falco-test: ## Send test Falco alert
	$(require_compose)
	@$(COMPOSE) --profile debug run --rm nats-cli \
		nats pub cicdecoy.security.falco.test.testpod \
		'{"output":"ESCAPE ATTEMPT: Mount syscall in decoy","priority":"Critical","rule":"CICDecoy — Mount syscall in decoy","time":"$(shell date -u +%Y-%m-%dT%H:%M:%S.000000000Z)","output_fields":{"k8s.pod.name":"ssh-decoy-test","k8s.ns.name":"decoys-production","container.name":"ssh-decoy","proc.name":"mount","proc.cmdline":"mount -t proc proc /mnt","user.name":"root"}}' \
		-s nats://nats:4222

falco-stats: ## Show Falco correlator stats
	$(require_compose)
	@$(COMPOSE) logs cti-collector 2>&1 | grep -i "falco" | tail -20

clean: ## Remove all data volumes
	$(require_compose)
	$(COMPOSE) --profile tier3 --profile debug --profile security down -v

reset: ## Full reset (volumes + images)
	$(require_compose)
	$(COMPOSE) --profile tier3 --profile debug --profile security down -v --rmi local

e2e-k3d: ## Run k3d E2E smoke test locally
	$(call require_cmd,k3d,k3d,https://k3d.io)
	$(call require_cmd,helm,helm,https://helm.sh)
	$(call require_cmd,kubectl,kubectl,https://kubernetes.io/docs/tasks/tools)
	bash tests/e2e/local_run.sh
