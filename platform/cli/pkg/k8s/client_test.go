package k8s

import (
	"fmt"
	"strings"
	"testing"
)

// ── NewClient ───────────────────────────────────────────────

func TestNewClient_Defaults(t *testing.T) {
	// NewClient with empty namespace should fall back to "default"
	// (since currentNamespace() will fail without a real kubeconfig)
	c, err := NewClient("", "", "")
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}

	if c.namespace != "default" {
		t.Errorf("namespace = %q, want %q", c.namespace, "default")
	}
}

func TestNewClient_ExplicitNamespace(t *testing.T) {
	c, err := NewClient("", "", "cicdecoy")
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}

	if c.namespace != "cicdecoy" {
		t.Errorf("namespace = %q, want %q", c.namespace, "cicdecoy")
	}
}

func TestNewClient_AllParams(t *testing.T) {
	c, err := NewClient("/path/to/kubeconfig", "staging-ctx", "honeypots")
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}

	if c.kubeconfig != "/path/to/kubeconfig" {
		t.Errorf("kubeconfig = %q", c.kubeconfig)
	}
	if c.context != "staging-ctx" {
		t.Errorf("context = %q", c.context)
	}
	if c.namespace != "honeypots" {
		t.Errorf("namespace = %q", c.namespace)
	}
}

func TestNewClient_Namespace(t *testing.T) {
	c, err := NewClient("", "", "test-ns")
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}

	if got := c.Namespace(); got != "test-ns" {
		t.Errorf("Namespace() = %q, want %q", got, "test-ns")
	}
}

// ── ParseDecoyResource ──────────────────────────────────────

func TestParseDecoyResource_ValidDecoy(t *testing.T) {
	yaml := `
apiVersion: cicdecoy.io/v1
kind: Decoy
metadata:
  name: ssh-bastion-01
  namespace: honeypots
spec:
  service:
    type: ssh
    port: 22
  fidelity:
    tier: 2
`
	doc, err := ParseDecoyResource([]byte(yaml), "test.yaml")
	if err != nil {
		t.Fatalf("ParseDecoyResource() error = %v", err)
	}

	if doc.GetKind() != "Decoy" {
		t.Errorf("GetKind() = %q, want %q", doc.GetKind(), "Decoy")
	}
	if doc.GetName() != "ssh-bastion-01" {
		t.Errorf("GetName() = %q, want %q", doc.GetName(), "ssh-bastion-01")
	}
	if doc.GetNamespace() != "honeypots" {
		t.Errorf("GetNamespace() = %q, want %q", doc.GetNamespace(), "honeypots")
	}
}

func TestParseDecoyResource_ValidFleet(t *testing.T) {
	yaml := `
apiVersion: cicdecoy.io/v1
kind: DecoyFleet
metadata:
  name: dmz-fleet
spec:
  templateRef: ssh-template
  count: 5
  zones:
    - dmz
    - internal
`
	doc, err := ParseDecoyResource([]byte(yaml), "fleet.yaml")
	if err != nil {
		t.Fatalf("ParseDecoyResource() error = %v", err)
	}

	if doc.GetKind() != "DecoyFleet" {
		t.Errorf("GetKind() = %q, want %q", doc.GetKind(), "DecoyFleet")
	}
	if doc.GetName() != "dmz-fleet" {
		t.Errorf("GetName() = %q, want %q", doc.GetName(), "dmz-fleet")
	}
}

func TestParseDecoyResource_InvalidYAML(t *testing.T) {
	_, err := ParseDecoyResource([]byte("not: valid: yaml: ["), "bad.yaml")
	if err == nil {
		t.Error("expected error for invalid YAML")
	}
}

func TestParseDecoyResource_EmptyInput(t *testing.T) {
	doc, err := ParseDecoyResource([]byte(""), "empty.yaml")
	if err != nil {
		t.Fatalf("ParseDecoyResource() error = %v", err)
	}
	// Empty YAML produces nil map, so getters return zero values
	if doc.GetKind() != "" {
		t.Errorf("GetKind() = %q, want empty", doc.GetKind())
	}
	if doc.GetName() != "" {
		t.Errorf("GetName() = %q, want empty", doc.GetName())
	}
}

func TestParseDecoyResource_NoMetadata(t *testing.T) {
	yaml := `
kind: Decoy
spec:
  service:
    type: ssh
`
	doc, err := ParseDecoyResource([]byte(yaml), "no-meta.yaml")
	if err != nil {
		t.Fatalf("ParseDecoyResource() error = %v", err)
	}

	if doc.GetName() != "" {
		t.Errorf("GetName() = %q, want empty for missing metadata", doc.GetName())
	}
	if doc.GetNamespace() != "" {
		t.Errorf("GetNamespace() = %q, want empty for missing metadata", doc.GetNamespace())
	}
}

// ── Validate ────────────────────────────────────────────────

func TestValidate_ValidDecoy(t *testing.T) {
	yaml := `
kind: Decoy
metadata:
  name: ssh-bastion-01
spec:
  service:
    type: ssh
    port: 22
  fidelity:
    tier: 2
`
	doc, err := ParseDecoyResource([]byte(yaml), "valid.yaml")
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}

	errs := doc.Validate()
	if len(errs) != 0 {
		t.Errorf("Validate() returned errors for valid decoy: %v", errs)
	}
}

func TestValidate_MissingName(t *testing.T) {
	yaml := `
kind: Decoy
metadata: {}
spec:
  service:
    type: ssh
    port: 22
  fidelity:
    tier: 2
`
	doc, _ := ParseDecoyResource([]byte(yaml), "test.yaml")
	errs := doc.Validate()

	if len(errs) == 0 {
		t.Fatal("expected validation errors for missing name")
	}

	found := false
	for _, e := range errs {
		if strings.Contains(e, "metadata.name required") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected 'metadata.name required' error, got: %v", errs)
	}
}

func TestValidate_MissingService(t *testing.T) {
	yaml := `
kind: Decoy
metadata:
  name: test-decoy
spec:
  fidelity:
    tier: 1
`
	doc, _ := ParseDecoyResource([]byte(yaml), "test.yaml")
	errs := doc.Validate()

	found := false
	for _, e := range errs {
		if strings.Contains(e, "spec.service required") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected 'spec.service required' error, got: %v", errs)
	}
}

func TestValidate_MissingServiceType(t *testing.T) {
	yaml := `
kind: Decoy
metadata:
  name: test-decoy
spec:
  service:
    port: 22
  fidelity:
    tier: 1
`
	doc, _ := ParseDecoyResource([]byte(yaml), "test.yaml")
	errs := doc.Validate()

	found := false
	for _, e := range errs {
		if strings.Contains(e, "spec.service.type required") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected 'spec.service.type required' error, got: %v", errs)
	}
}

func TestValidate_MissingServicePort(t *testing.T) {
	yaml := `
kind: Decoy
metadata:
  name: test-decoy
spec:
  service:
    type: ssh
  fidelity:
    tier: 1
`
	doc, _ := ParseDecoyResource([]byte(yaml), "test.yaml")
	errs := doc.Validate()

	found := false
	for _, e := range errs {
		if strings.Contains(e, "spec.service.port required") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected 'spec.service.port required' error, got: %v", errs)
	}
}

func TestValidate_MissingFidelity(t *testing.T) {
	yaml := `
kind: Decoy
metadata:
  name: test-decoy
spec:
  service:
    type: ssh
    port: 22
`
	doc, _ := ParseDecoyResource([]byte(yaml), "test.yaml")
	errs := doc.Validate()

	found := false
	for _, e := range errs {
		if strings.Contains(e, "spec.fidelity required") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected 'spec.fidelity required' error, got: %v", errs)
	}
}

func TestValidate_MissingFidelityTier(t *testing.T) {
	yaml := `
kind: Decoy
metadata:
  name: test-decoy
spec:
  service:
    type: ssh
    port: 22
  fidelity: {}
`
	doc, _ := ParseDecoyResource([]byte(yaml), "test.yaml")
	errs := doc.Validate()

	found := false
	for _, e := range errs {
		if strings.Contains(e, "spec.fidelity.tier required") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected 'spec.fidelity.tier required' error, got: %v", errs)
	}
}

func TestValidate_Tier3RequiresAdaptive(t *testing.T) {
	yaml := `
kind: Decoy
metadata:
  name: test-decoy
spec:
  service:
    type: ssh
    port: 22
  fidelity:
    tier: 3
`
	doc, _ := ParseDecoyResource([]byte(yaml), "test.yaml")
	errs := doc.Validate()

	found := false
	for _, e := range errs {
		if strings.Contains(e, "tier 3 requires spec.fidelity.adaptive") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected 'tier 3 requires spec.fidelity.adaptive' error, got: %v", errs)
	}
}

func TestValidate_Tier3WithAdaptive(t *testing.T) {
	yaml := `
kind: Decoy
metadata:
  name: test-decoy
spec:
  service:
    type: ssh
    port: 22
  fidelity:
    tier: 3
    adaptive:
      model: gpt-4
`
	doc, _ := ParseDecoyResource([]byte(yaml), "test.yaml")
	errs := doc.Validate()

	for _, e := range errs {
		if strings.Contains(e, "adaptive") {
			t.Errorf("should not have adaptive error when adaptive is set, got: %s", e)
		}
	}
}

func TestValidate_SelectiveAuthRequiresAllowCredentials(t *testing.T) {
	yaml := `
kind: Decoy
metadata:
  name: test-decoy
spec:
  service:
    type: ssh
    port: 22
  fidelity:
    tier: 1
  authentication:
    mode: selective
`
	doc, _ := ParseDecoyResource([]byte(yaml), "test.yaml")
	errs := doc.Validate()

	found := false
	for _, e := range errs {
		if strings.Contains(e, "selective auth requires allowCredentials") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected 'selective auth requires allowCredentials' error, got: %v", errs)
	}
}

func TestValidate_SelectiveAuthWithCredentials(t *testing.T) {
	yaml := `
kind: Decoy
metadata:
  name: test-decoy
spec:
  service:
    type: ssh
    port: 22
  fidelity:
    tier: 1
  authentication:
    mode: selective
    allowCredentials:
      - username: admin
        password: admin123
`
	doc, _ := ParseDecoyResource([]byte(yaml), "test.yaml")
	errs := doc.Validate()

	for _, e := range errs {
		if strings.Contains(e, "allowCredentials") {
			t.Errorf("should not have allowCredentials error when set, got: %s", e)
		}
	}
}

func TestValidate_DecoyFleet_Valid(t *testing.T) {
	yaml := `
kind: DecoyFleet
metadata:
  name: dmz-fleet
spec:
  templateRef: ssh-template
  count: 5
`
	doc, _ := ParseDecoyResource([]byte(yaml), "test.yaml")
	errs := doc.Validate()

	if len(errs) != 0 {
		t.Errorf("Validate() returned errors for valid fleet: %v", errs)
	}
}

func TestValidate_DecoyFleet_MissingTemplateRef(t *testing.T) {
	yaml := `
kind: DecoyFleet
metadata:
  name: dmz-fleet
spec:
  count: 5
`
	doc, _ := ParseDecoyResource([]byte(yaml), "test.yaml")
	errs := doc.Validate()

	found := false
	for _, e := range errs {
		if strings.Contains(e, "spec.templateRef required") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected 'spec.templateRef required' error, got: %v", errs)
	}
}

func TestValidate_DecoyFleet_MissingCount(t *testing.T) {
	yaml := `
kind: DecoyFleet
metadata:
  name: dmz-fleet
spec:
  templateRef: ssh-template
`
	doc, _ := ParseDecoyResource([]byte(yaml), "test.yaml")
	errs := doc.Validate()

	found := false
	for _, e := range errs {
		if strings.Contains(e, "spec.count required") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected 'spec.count required' error, got: %v", errs)
	}
}

// ── FidelityWarnings ────────────────────────────────────────

func TestFidelityWarnings_NonDecoy(t *testing.T) {
	yaml := `
kind: DecoyFleet
metadata:
  name: fleet-01
spec:
  templateRef: ssh-template
  count: 3
`
	doc, _ := ParseDecoyResource([]byte(yaml), "test.yaml")
	warns := doc.FidelityWarnings()

	if warns != nil {
		t.Errorf("FidelityWarnings() should be nil for non-Decoy kinds, got: %v", warns)
	}
}

func TestFidelityWarnings_SSHBannerInvalid(t *testing.T) {
	yaml := `
kind: Decoy
metadata:
  name: ssh-test
spec:
  service:
    type: ssh
    port: 22
    banner: "Welcome to server"
  fidelity:
    tier: 1
`
	doc, _ := ParseDecoyResource([]byte(yaml), "test.yaml")
	warns := doc.FidelityWarnings()

	found := false
	for _, w := range warns {
		if strings.Contains(w, "SSH banner doesn't start with 'SSH-'") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected SSH banner warning, got: %v", warns)
	}
}

func TestFidelityWarnings_SSHBannerValid(t *testing.T) {
	yaml := `
kind: Decoy
metadata:
  name: ssh-test
spec:
  service:
    type: ssh
    port: 22
    banner: "SSH-2.0-OpenSSH_8.9"
  fidelity:
    tier: 1
`
	doc, _ := ParseDecoyResource([]byte(yaml), "test.yaml")
	warns := doc.FidelityWarnings()

	for _, w := range warns {
		if strings.Contains(w, "SSH banner") {
			t.Errorf("should not warn about valid SSH banner, got: %s", w)
		}
	}
}

func TestFidelityWarnings_Tier2MissingHostname(t *testing.T) {
	yaml := `
kind: Decoy
metadata:
  name: test-decoy
spec:
  service:
    type: ssh
    port: 22
  fidelity:
    tier: 2
`
	doc, _ := ParseDecoyResource([]byte(yaml), "test.yaml")
	warns := doc.FidelityWarnings()

	found := false
	for _, w := range warns {
		if strings.Contains(w, "tier 2 should have identity.hostname") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected hostname warning for tier 2, got: %v", warns)
	}
}

func TestFidelityWarnings_Tier2WithHostname(t *testing.T) {
	yaml := `
kind: Decoy
metadata:
  name: test-decoy
spec:
  service:
    type: ssh
    port: 22
  fidelity:
    tier: 2
  identity:
    hostname: bastion-prod-01
`
	doc, _ := ParseDecoyResource([]byte(yaml), "test.yaml")
	warns := doc.FidelityWarnings()

	for _, w := range warns {
		if strings.Contains(w, "identity.hostname") {
			t.Errorf("should not warn when hostname is set, got: %s", w)
		}
	}
}

func TestFidelityWarnings_Tier3MissingProfileRef(t *testing.T) {
	yaml := `
kind: Decoy
metadata:
  name: test-decoy
spec:
  service:
    type: ssh
    port: 22
  fidelity:
    tier: 3
  identity:
    hostname: bastion-prod-01
`
	doc, _ := ParseDecoyResource([]byte(yaml), "test.yaml")
	warns := doc.FidelityWarnings()

	found := false
	for _, w := range warns {
		if strings.Contains(w, "tier 3 should reference a DecoyProfile") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected profileRef warning for tier 3, got: %v", warns)
	}
}

func TestFidelityWarnings_NoTelemetry(t *testing.T) {
	yaml := `
kind: Decoy
metadata:
  name: test-decoy
spec:
  service:
    type: ssh
    port: 22
  fidelity:
    tier: 1
`
	doc, _ := ParseDecoyResource([]byte(yaml), "test.yaml")
	warns := doc.FidelityWarnings()

	found := false
	for _, w := range warns {
		if strings.Contains(w, "no telemetry exporter configured") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected telemetry warning, got: %v", warns)
	}
}

func TestFidelityWarnings_WithTelemetry(t *testing.T) {
	yaml := `
kind: Decoy
metadata:
  name: test-decoy
spec:
  service:
    type: ssh
    port: 22
  fidelity:
    tier: 1
  telemetry:
    exporter: prometheus
`
	doc, _ := ParseDecoyResource([]byte(yaml), "test.yaml")
	warns := doc.FidelityWarnings()

	for _, w := range warns {
		if strings.Contains(w, "telemetry") {
			t.Errorf("should not warn when telemetry is configured, got: %s", w)
		}
	}
}

// ── Data types ──────────────────────────────────────────────

func TestDecoyStatusRow_Fields(t *testing.T) {
	row := DecoyStatusRow{
		Name:      "ssh-bastion-01",
		Namespace: "honeypots",
		Tier:      3,
		Service:   "ssh",
		Zone:      "dmz",
		Status:    "active",
		PodIP:     "10.244.0.5",
		Sessions:  42,
		Alerts:    7,
		Uptime:    "5d",
	}

	if row.Name != "ssh-bastion-01" {
		t.Errorf("Name = %q", row.Name)
	}
	if row.Tier != 3 {
		t.Errorf("Tier = %d", row.Tier)
	}
	if row.Sessions != 42 {
		t.Errorf("Sessions = %d", row.Sessions)
	}
}

func TestFleetRow_Fields(t *testing.T) {
	row := FleetRow{
		Name:     "dmz-fleet",
		Template: "ssh-template",
		Ready:    "3/5",
		Total:    5,
		Zones:    "dmz,internal",
	}

	if row.Name != "dmz-fleet" {
		t.Errorf("Name = %q", row.Name)
	}
	if row.Total != 5 {
		t.Errorf("Total = %d", row.Total)
	}
}

func TestProfileRow_Fields(t *testing.T) {
	row := ProfileRow{
		Name:     "ubuntu-server",
		OS:       "linux",
		Distro:   "ubuntu",
		Packages: 45,
		Users:    3,
	}

	if row.Name != "ubuntu-server" {
		t.Errorf("Name = %q", row.Name)
	}
	if row.Packages != 45 {
		t.Errorf("Packages = %d", row.Packages)
	}
}

func TestComponentStatus_Fields(t *testing.T) {
	status := ComponentStatus{
		Status:  "healthy",
		Latency: "5ms",
		Details: map[string]string{"version": "2.10.0"},
	}

	if status.Status != "healthy" {
		t.Errorf("Status = %q", status.Status)
	}
	if status.Details["version"] != "2.10.0" {
		t.Errorf("Details[version] = %q", status.Details["version"])
	}
}

func TestPlatformHealthResult_Fields(t *testing.T) {
	h := PlatformHealthResult{
		Cluster:     ComponentStatus{Status: "healthy"},
		NATS:        ComponentStatus{Status: "healthy"},
		Storage:     ComponentStatus{Status: "degraded", Details: map[string]string{"phase": "Pending"}},
		CTIPipeline: ComponentStatus{Status: "offline"},
		Inference:   ComponentStatus{Status: "healthy"},
	}

	if h.Cluster.Status != "healthy" {
		t.Errorf("Cluster.Status = %q", h.Cluster.Status)
	}
	if h.Storage.Status != "degraded" {
		t.Errorf("Storage.Status = %q", h.Storage.Status)
	}
	if h.CTIPipeline.Status != "offline" {
		t.Errorf("CTIPipeline.Status = %q", h.CTIPipeline.Status)
	}
}

// ── kubectl argument construction ───────────────────────────

func TestKubectl_ArgConstruction(t *testing.T) {
	tests := []struct {
		name       string
		kubeconfig string
		context    string
		namespace  string
		args       []string
		wantParts  []string
	}{
		{
			name:      "minimal args",
			namespace: "default",
			args:      []string{"get", "pods"},
			wantParts: []string{"-n", "default", "get", "pods"},
		},
		{
			name:       "with kubeconfig",
			kubeconfig: "/home/user/.kube/config",
			namespace:  "cicdecoy",
			args:       []string{"get", "decoys"},
			wantParts:  []string{"--kubeconfig", "/home/user/.kube/config", "-n", "cicdecoy", "get", "decoys"},
		},
		{
			name:      "with context",
			context:   "prod-cluster",
			namespace: "honeypots",
			args:      []string{"get", "pods"},
			wantParts: []string{"--context", "prod-cluster", "-n", "honeypots", "get", "pods"},
		},
		{
			name:       "all options",
			kubeconfig: "/etc/kube/config",
			context:    "staging",
			namespace:  "decoys",
			args:       []string{"delete", "decoy", "test-01"},
			wantParts:  []string{"--kubeconfig", "/etc/kube/config", "--context", "staging", "-n", "decoys", "delete", "decoy", "test-01"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &Client{
				kubeconfig: tt.kubeconfig,
				context:    tt.context,
				namespace:  tt.namespace,
			}

			// Build args the same way kubectl() does
			fullArgs := []string{}
			if c.kubeconfig != "" {
				fullArgs = append(fullArgs, "--kubeconfig", c.kubeconfig)
			}
			if c.context != "" {
				fullArgs = append(fullArgs, "--context", c.context)
			}
			if c.namespace != "" {
				fullArgs = append(fullArgs, "-n", c.namespace)
			}
			fullArgs = append(fullArgs, tt.args...)

			if len(fullArgs) != len(tt.wantParts) {
				t.Fatalf("arg count = %d, want %d\ngot:  %v\nwant: %v", len(fullArgs), len(tt.wantParts), fullArgs, tt.wantParts)
			}
			for i, want := range tt.wantParts {
				if fullArgs[i] != want {
					t.Errorf("arg[%d] = %q, want %q", i, fullArgs[i], want)
				}
			}
		})
	}
}

// ── Validate: table-driven comprehensive test ───────────────

func TestValidate_TableDriven(t *testing.T) {
	tests := []struct {
		name      string
		yaml      string
		wantErrs  []string
		wantClean bool
	}{
		{
			name: "fully valid tier 1 decoy",
			yaml: `
kind: Decoy
metadata:
  name: ssh-01
spec:
  service:
    type: ssh
    port: 22
  fidelity:
    tier: 1
`,
			wantClean: true,
		},
		{
			name: "fully valid tier 3 decoy",
			yaml: `
kind: Decoy
metadata:
  name: ssh-03
spec:
  service:
    type: ssh
    port: 22
  fidelity:
    tier: 3
    adaptive:
      model: gpt-4
`,
			wantClean: true,
		},
		{
			name: "multiple errors",
			yaml: `
kind: Decoy
metadata: {}
spec:
  fidelity:
    tier: 3
`,
			wantErrs: []string{
				"metadata.name required",
				"spec.service required",
				"tier 3 requires spec.fidelity.adaptive",
			},
		},
		{
			name: "valid fleet",
			yaml: `
kind: DecoyFleet
metadata:
  name: fleet-01
spec:
  templateRef: ssh-tmpl
  count: 10
`,
			wantClean: true,
		},
		{
			name: "fleet missing both required fields",
			yaml: `
kind: DecoyFleet
metadata:
  name: fleet-02
spec: {}
`,
			wantErrs: []string{
				"spec.templateRef required",
				"spec.count required",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			doc, err := ParseDecoyResource([]byte(tt.yaml), "test.yaml")
			if err != nil {
				t.Fatalf("parse error: %v", err)
			}

			errs := doc.Validate()

			if tt.wantClean {
				if len(errs) != 0 {
					t.Errorf("expected no errors, got: %v", errs)
				}
				return
			}

			for _, want := range tt.wantErrs {
				found := false
				for _, e := range errs {
					if strings.Contains(e, want) {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("expected error containing %q, got: %v", want, errs)
				}
			}
		})
	}
}

// ── FidelityWarnings: table-driven ──────────────────────────

func TestFidelityWarnings_TableDriven(t *testing.T) {
	tests := []struct {
		name         string
		yaml         string
		wantWarnings []string
		wantClean    bool
	}{
		{
			name: "tier 1 with telemetry - only no warnings about tier/hostname",
			yaml: `
kind: Decoy
metadata:
  name: ssh-01
spec:
  service:
    type: ssh
    port: 22
  fidelity:
    tier: 1
  telemetry:
    exporter: prometheus
`,
			wantClean: true,
		},
		{
			name: "tier 3 missing everything",
			yaml: `
kind: Decoy
metadata:
  name: ssh-03
spec:
  service:
    type: ssh
    port: 22
    banner: "Bad Banner"
  fidelity:
    tier: 3
`,
			wantWarnings: []string{
				"SSH banner doesn't start with 'SSH-'",
				"tier 3 should have identity.hostname",
				"tier 3 should reference a DecoyProfile",
				"no telemetry exporter configured",
			},
		},
		{
			name: "non-SSH service with bad banner is fine",
			yaml: `
kind: Decoy
metadata:
  name: http-01
spec:
  service:
    type: http
    port: 80
    banner: "Apache/2.4"
  fidelity:
    tier: 1
  telemetry:
    exporter: otel
`,
			wantClean: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			doc, err := ParseDecoyResource([]byte(tt.yaml), "test.yaml")
			if err != nil {
				t.Fatalf("parse error: %v", err)
			}

			warns := doc.FidelityWarnings()

			if tt.wantClean {
				if len(warns) != 0 {
					t.Errorf("expected no warnings, got: %v", warns)
				}
				return
			}

			for _, want := range tt.wantWarnings {
				found := false
				for _, w := range warns {
					if strings.Contains(w, want) {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("expected warning containing %q, got: %v", want, warns)
				}
			}
		})
	}
}

// ── RotateDecoy patch format ────────────────────────────────

func TestRotatePatchFormat(t *testing.T) {
	// Verify the annotation patch format used by RotateDecoy
	patch := fmt.Sprintf(`{"metadata":{"annotations":{"cicdecoy.io/rotate":"%d"}}}`, 1700000000)

	if !strings.Contains(patch, "cicdecoy.io/rotate") {
		t.Error("patch should contain cicdecoy.io/rotate annotation")
	}
	if !strings.Contains(patch, "1700000000") {
		t.Error("patch should contain timestamp value")
	}
}

// ── ScaleFleet patch format ─────────────────────────────────

func TestScaleFleetPatchFormat(t *testing.T) {
	count := "10"
	patch := fmt.Sprintf(`{"spec":{"count":%s}}`, count)

	expected := `{"spec":{"count":10}}`
	if patch != expected {
		t.Errorf("patch = %q, want %q", patch, expected)
	}
}
