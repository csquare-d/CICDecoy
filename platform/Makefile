# CI/CDecoy — Build & Deploy
# Run from repo root (MVP/)

REGISTRY   ?= localhost:5000
TAG        ?= dev
NAMESPACE  ?= cicdecoy-system
RELEASE    ?= cicdecoy
CHART      ?= helm/cicdecoy

IMAGES = ssh-decoy cti dashboard inference

# ── Build ────────────────────────────────────────────

.PHONY: build build-% push push-% all

build: $(addprefix build-,$(IMAGES))

build-ssh-decoy:
	docker build -t $(REGISTRY)/cicdecoy-ssh:$(TAG) ssh-decoy/

build-cti:
	docker build -t $(REGISTRY)/cicdecoy-cti-pipeline:$(TAG) cti/

build-dashboard:
	docker build -t $(REGISTRY)/cicdecoy-dashboard:$(TAG) dashboard/

build-inference:
	docker build -t $(REGISTRY)/cicdecoy-inference:$(TAG) inference/

push: $(addprefix push-,$(IMAGES))

push-%: build-%
	docker push $(REGISTRY)/cicdecoy-$*:$(TAG)

# ── k3s (import images directly, no registry needed) ─

.PHONY: k3s-import
k3s-import: build
	@for img in $(IMAGES); do \
		echo "Importing cicdecoy-$$img:$(TAG) into k3s..."; \
		docker save $(REGISTRY)/cicdecoy-$$img:$(TAG) | sudo k3s ctr images import -; \
	done

# ── Helm ─────────────────────────────────────────────

.PHONY: helm-deps helm-install helm-upgrade helm-uninstall helm-template

helm-deps:
	helm dependency update $(CHART)

helm-install: helm-deps
	helm install $(RELEASE) $(CHART) \
		-n $(NAMESPACE) --create-namespace \
		-f helm/values-dev.yaml

helm-upgrade:
	helm upgrade $(RELEASE) $(CHART) \
		-n $(NAMESPACE) \
		-f helm/values-dev.yaml

helm-uninstall:
	helm uninstall $(RELEASE) -n $(NAMESPACE)

helm-template:
	helm template $(RELEASE) $(CHART) -f helm/values-dev.yaml

# ── CLI (Go) ─────────────────────────────────────────

.PHONY: cli-build cli-install
cli-build:
	cd cli && CGO_ENABLED=0 go build -ldflags="-s -w" -o ../bin/cicdecoy .

cli-install: cli-build
	cp bin/cicdecoy /usr/local/bin/cicdecoy
	@echo "Installed: $(shell which cicdecoy)"

# ── Full deploy (k3s) ────────────────────────────────

.PHONY: deploy
deploy: build k3s-import helm-install
	@echo "Waiting for pods..."
	kubectl -n $(NAMESPACE) rollout status deployment/$(RELEASE)-operator --timeout=120s
	kubectl -n $(NAMESPACE) rollout status deployment/$(RELEASE)-cti-pipeline --timeout=120s
	kubectl -n $(NAMESPACE) rollout status deployment/$(RELEASE)-dashboard --timeout=120s
	@echo ""
	@echo "Dashboard: http://$$(hostname -I | awk '{print $$1}'):30080"

# ── Dev helpers ──────────────────────────────────────

.PHONY: logs-pipeline logs-dashboard logs-operator status

logs-pipeline:
	kubectl -n $(NAMESPACE) logs -f deploy/$(RELEASE)-cti-pipeline

logs-dashboard:
	kubectl -n $(NAMESPACE) logs -f deploy/$(RELEASE)-dashboard

logs-operator:
	kubectl -n $(NAMESPACE) logs -f deploy/$(RELEASE)-operator

status:
	@echo "=== Pods ==="
	@kubectl -n $(NAMESPACE) get pods
	@echo ""
	@echo "=== Decoys ==="
	@kubectl get decoys -A 2>/dev/null || echo "(no decoys deployed)"
	@echo ""
	@echo "=== HoneyTokens ==="
	@kubectl get honeytokens -A 2>/dev/null || echo "(no honeytokens deployed)"
	@echo ""
	@echo "=== NATS Streams ==="
	@kubectl -n $(NAMESPACE) exec deploy/$(RELEASE)-nats -- nats stream ls 2>/dev/null || echo "(nats not ready)"

.PHONY: test
test:
	cd tests && pip install -r requirements.txt && pytest -v

.PHONY: clean
clean: helm-uninstall
	kubectl delete namespace $(NAMESPACE) --ignore-not-found
	kubectl delete namespace decoys-production --ignore-not-found
	kubectl delete namespace decoys-staging --ignore-not-found
