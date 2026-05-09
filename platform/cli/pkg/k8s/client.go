package k8s

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"sigs.k8s.io/yaml"
)

// defaultCmdTimeout is the maximum time a kubectl command may run before
// being killed.  Individual callers can use kubectlCtx to supply a
// tighter deadline.
const defaultCmdTimeout = 30 * time.Second

// Client wraps kubectl and the Kubernetes API for CI/CDecoy CRD operations.
type Client struct {
	kubeconfig string
	context    string
	namespace  string
}

// DecoyResource represents a parsed CI/CDecoy YAML manifest.
type DecoyResource struct {
	raw       map[string]interface{}
	source    string
	rawBytes  []byte
}

func NewClient(kubeconfig, ctx, namespace string) (*Client, error) {
	c := &Client{
		kubeconfig: kubeconfig,
		context:    ctx,
		namespace:  namespace,
	}
	if namespace == "" {
		c.namespace = c.currentNamespace()
	}
	if c.namespace == "" {
		c.namespace = "default"
	}
	return c, nil
}

func (c *Client) Namespace() string { return c.namespace }

func (c *Client) kubectl(args ...string) ([]byte, error) {
	return c.kubectlCtx(context.Background(), args...)
}

func (c *Client) kubectlCtx(ctx context.Context, args ...string) ([]byte, error) {
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, defaultCmdTimeout)
		defer cancel()
	}
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
	fullArgs = append(fullArgs, args...)
	cmd := exec.CommandContext(ctx, "kubectl", fullArgs...)
	out, err := cmd.CombinedOutput()
	if ctx.Err() == context.DeadlineExceeded {
		return out, fmt.Errorf("kubectl timed out after %s: %s", defaultCmdTimeout, strings.Join(args, " "))
	}
	return out, err
}

func (c *Client) currentNamespace() string {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "kubectl", "config", "view", "--minify", "-o", "jsonpath={.contexts[0].context.namespace}")
	out, err := cmd.Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

// ── CRD Operations ────────────────────────────────────

func ParseDecoyResource(data []byte, source string) (DecoyResource, error) {
	var raw map[string]interface{}
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return DecoyResource{}, err
	}
	return DecoyResource{raw: raw, source: source, rawBytes: data}, nil
}

func (d DecoyResource) GetKind() string {
	k, _ := d.raw["kind"].(string)
	return k
}

func (d DecoyResource) GetName() string {
	meta, ok := d.raw["metadata"].(map[string]interface{})
	if !ok {
		return ""
	}
	name, _ := meta["name"].(string)
	return name
}

func (d DecoyResource) GetNamespace() string {
	meta, ok := d.raw["metadata"].(map[string]interface{})
	if !ok {
		return ""
	}
	ns, _ := meta["namespace"].(string)
	return ns
}

func (d DecoyResource) Validate() []string {
	var errs []string
	kind := d.GetKind()
	name := d.GetName()
	spec, _ := d.raw["spec"].(map[string]interface{})

	if name == "" {
		errs = append(errs, fmt.Sprintf("%s: metadata.name required", kind))
	}

	if kind == "Decoy" {
		svc, _ := spec["service"].(map[string]interface{})
		if svc == nil {
			errs = append(errs, fmt.Sprintf("%s: spec.service required", name))
		} else {
			if svc["type"] == nil {
				errs = append(errs, fmt.Sprintf("%s: spec.service.type required", name))
			}
			if svc["port"] == nil {
				errs = append(errs, fmt.Sprintf("%s: spec.service.port required", name))
			}
		}

		fid, _ := spec["fidelity"].(map[string]interface{})
		if fid == nil {
			errs = append(errs, fmt.Sprintf("%s: spec.fidelity required", name))
		} else {
			tier, _ := fid["tier"].(float64)
			if tier == 0 {
				errs = append(errs, fmt.Sprintf("%s: spec.fidelity.tier required", name))
			}
			if tier == 3 && fid["adaptive"] == nil {
				errs = append(errs, fmt.Sprintf("%s: tier 3 requires spec.fidelity.adaptive", name))
			}
		}

		auth, _ := spec["authentication"].(map[string]interface{})
		if auth != nil {
			mode, _ := auth["mode"].(string)
			if mode == "selective" && auth["allowCredentials"] == nil {
				errs = append(errs, fmt.Sprintf("%s: selective auth requires allowCredentials", name))
			}
		}
	}

	if kind == "DecoyFleet" {
		if spec["templateRef"] == nil {
			errs = append(errs, fmt.Sprintf("%s: spec.templateRef required", name))
		}
		if spec["count"] == nil {
			errs = append(errs, fmt.Sprintf("%s: spec.count required", name))
		}
	}

	return errs
}

func (d DecoyResource) FidelityWarnings() []string {
	var warns []string
	if d.GetKind() != "Decoy" {
		return nil
	}

	spec, _ := d.raw["spec"].(map[string]interface{})
	svc, _ := spec["service"].(map[string]interface{})
	fid, _ := spec["fidelity"].(map[string]interface{})
	ident, _ := spec["identity"].(map[string]interface{})

	tier, _ := fid["tier"].(float64)
	banner, _ := svc["banner"].(string)
	svcType, _ := svc["type"].(string)

	if svcType == "ssh" && banner != "" && !strings.HasPrefix(banner, "SSH-") {
		warns = append(warns, fmt.Sprintf("%s: SSH banner doesn't start with 'SSH-'", d.GetName()))
	}

	if tier >= 2 {
		hostname, _ := ident["hostname"].(string)
		if hostname == "" {
			warns = append(warns, fmt.Sprintf("%s: tier %.0f should have identity.hostname", d.GetName(), tier))
		}
	}

	if tier == 3 {
		profileRef, _ := ident["profileRef"].(string)
		if profileRef == "" {
			warns = append(warns, fmt.Sprintf("%s: tier 3 should reference a DecoyProfile", d.GetName()))
		}
	}

	if spec["telemetry"] == nil {
		warns = append(warns, fmt.Sprintf("%s: no telemetry exporter configured", d.GetName()))
	}

	return warns
}

func (c *Client) ApplyDecoy(doc DecoyResource) error {
	ns := doc.GetNamespace()
	if ns == "" {
		ns = c.namespace
	}

	ctx, cancel := context.WithTimeout(context.Background(), defaultCmdTimeout)
	defer cancel()

	fullArgs := []string{}
	if c.kubeconfig != "" {
		fullArgs = append(fullArgs, "--kubeconfig", c.kubeconfig)
	}
	if c.context != "" {
		fullArgs = append(fullArgs, "--context", c.context)
	}
	fullArgs = append(fullArgs, "-n", ns, "apply", "-f", "-")
	cmd := exec.CommandContext(ctx, "kubectl", fullArgs...)
	cmd.Stdin = strings.NewReader(string(doc.rawBytes))
	out, err := cmd.CombinedOutput()
	if ctx.Err() == context.DeadlineExceeded {
		return fmt.Errorf("kubectl apply timed out after %s", defaultCmdTimeout)
	}
	if err != nil {
		return fmt.Errorf("%s: %s", err, string(out))
	}
	return nil
}

func (c *Client) WaitForDecoys(docs []DecoyResource, timeout string) error {
	dur, _ := time.ParseDuration(timeout)
	if dur == 0 {
		dur = 120 * time.Second
	}
	ctx, cancel := context.WithTimeout(context.Background(), dur)
	defer cancel()

	for _, doc := range docs {
		if doc.GetKind() != "Decoy" {
			continue
		}
		name := doc.GetName()
		ns := doc.GetNamespace()
		if ns == "" {
			ns = c.namespace
		}

		wait := 2 * time.Second
		maxWait := 30 * time.Second
		for {
			select {
			case <-ctx.Done():
				return fmt.Errorf("timeout waiting for %s", name)
			default:
			}

			out, err := c.kubectl("get", "decoy", name, "-n", ns, "-o", "jsonpath={.status.phase}")
			if err == nil && strings.TrimSpace(string(out)) == "Active" {
				break
			}
			time.Sleep(wait)
			if wait < maxWait {
				wait = wait * 2
				if wait > maxWait {
					wait = maxWait
				}
			}
		}
	}
	return nil
}

func (c *Client) DestroyDecoy(name string, cascade bool) error {
	args := []string{"delete", "decoy", name}
	_, err := c.kubectl(args...)
	return err
}

func (c *Client) DestroyAllDecoys(cascade bool) error {
	_, err := c.kubectl("delete", "decoy", "--all")
	return err
}

func (c *Client) RotateDecoy(name, strategy string) error {
	// Patch the decoy to trigger rotation via annotation
	patch := fmt.Sprintf(`{"metadata":{"annotations":{"cicdecoy.io/rotate":"%d"}}}`, time.Now().Unix())
	_, err := c.kubectl("patch", "decoy", name, "--type=merge", "-p", patch)
	return err
}

func (c *Client) RotateAllDecoys(strategy string) error {
	patch := fmt.Sprintf(`{"metadata":{"annotations":{"cicdecoy.io/rotate":"%d"}}}`, time.Now().Unix())
	out, err := c.kubectl("get", "decoys", "-o", "jsonpath={.items[*].metadata.name}")
	if err != nil {
		return fmt.Errorf("listing decoys for rotation: %w", err)
	}
	names := strings.Fields(string(out))
	var errs []error
	for _, name := range names {
		_, err := c.kubectl("patch", "decoy", name, "--type=merge", "-p", patch)
		if err != nil {
			errs = append(errs, fmt.Errorf("rotate %s: %w", name, err))
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("rotation failed for %d/%d decoys: %v", len(errs), len(names), errs[0])
	}
	return nil
}

// ── Listing / Health ──────────────────────────────────

type PlatformHealthResult struct {
	Cluster     ComponentStatus `json:"cluster"`
	NATS        ComponentStatus `json:"nats"`
	Storage     ComponentStatus `json:"storage"`
	CTIPipeline ComponentStatus `json:"ctiPipeline"`
	Inference   ComponentStatus `json:"inference"`
}

type ComponentStatus struct {
	Status  string            `json:"status"`
	Latency string            `json:"latency,omitempty"`
	Details map[string]string `json:"details,omitempty"`
}

type DecoyStatusRow struct {
	Name         string `json:"name"`
	Namespace    string `json:"namespace"`
	Tier         int    `json:"tier"`
	Service      string `json:"service"`
	Zone         string `json:"zone"`
	Status       string `json:"status"`
	PodIP        string `json:"podIP"`
	Sessions     int64  `json:"sessions"`
	Alerts       int64  `json:"alerts"`
	Uptime       string `json:"uptime"`
	LastRotation string `json:"lastRotation"`
}

func (c *Client) PlatformHealth() (PlatformHealthResult, error) {
	var h PlatformHealthResult

	// Check cluster
	if _, err := c.kubectl("cluster-info"); err == nil {
		h.Cluster = ComponentStatus{Status: "healthy"}
	} else {
		h.Cluster = ComponentStatus{Status: "offline"}
	}

	// Check NATS pod
	h.NATS = c.checkPodHealth("nats")
	h.Storage = c.checkPodHealth("timescaledb")
	h.CTIPipeline = c.checkPodHealth("cti-pipeline")
	h.Inference = c.checkPodHealth("inference")

	return h, nil
}

func (c *Client) checkPodHealth(component string) ComponentStatus {
	out, err := c.kubectl("get", "pods", "-l", fmt.Sprintf("app.kubernetes.io/component=%s", component),
		"-o", "jsonpath={.items[0].status.phase}")
	if err != nil || strings.TrimSpace(string(out)) == "" {
		return ComponentStatus{Status: "offline"}
	}
	phase := strings.TrimSpace(string(out))
	if phase == "Running" {
		return ComponentStatus{Status: "healthy"}
	}
	return ComponentStatus{Status: "degraded", Details: map[string]string{"phase": phase}}
}

func (c *Client) ListDecoys(tier, zone, svcType string) ([]DecoyStatusRow, error) {
	out, err := c.kubectl("get", "decoys", "--all-namespaces", "-o", "json")
	if err != nil {
		return nil, fmt.Errorf("listing decoys: %s", string(out))
	}

	var list struct {
		Items []struct {
			Metadata struct {
				Name      string            `json:"name"`
				Namespace string            `json:"namespace"`
				Labels    map[string]string `json:"labels"`
			} `json:"metadata"`
			Spec struct {
				Service  struct{ Type string; Port int } `json:"service"`
				Fidelity struct{ Tier int }              `json:"fidelity"`
			} `json:"spec"`
			Status struct {
				Phase            string `json:"phase"`
				InteractionCount int64  `json:"interactionCount"`
				PodName          string `json:"podName"`
			} `json:"status"`
		} `json:"items"`
	}

	if err := json.Unmarshal(out, &list); err != nil {
		return nil, err
	}

	var rows []DecoyStatusRow
	for _, item := range list.Items {
		row := DecoyStatusRow{
			Name:      item.Metadata.Name,
			Namespace: item.Metadata.Namespace,
			Tier:      item.Spec.Fidelity.Tier,
			Service:   item.Spec.Service.Type,
			Zone:      item.Metadata.Labels["cicdecoy.io/zone"],
			Status:    strings.ToLower(item.Status.Phase),
			Sessions:  item.Status.InteractionCount,
		}

		// Filter
		if tier != "" && fmt.Sprintf("%d", row.Tier) != tier {
			continue
		}
		if zone != "" && row.Zone != zone {
			continue
		}
		if svcType != "" && row.Service != svcType {
			continue
		}

		rows = append(rows, row)
	}

	return rows, nil
}

func (c *Client) ListFleets() ([]FleetRow, error) {
	out, err := c.kubectl("get", "decoyfleets", "--all-namespaces", "-o", "json")
	if err != nil {
		return nil, err
	}

	var list struct {
		Items []struct {
			Metadata struct{ Name string } `json:"metadata"`
			Spec     struct {
				TemplateRef string   `json:"templateRef"`
				Count       int      `json:"count"`
				Zones       []string `json:"zones"`
			} `json:"spec"`
			Status struct {
				ReadyCount string `json:"readyCount"`
			} `json:"status"`
		} `json:"items"`
	}
	if err := json.Unmarshal(out, &list); err != nil {
		return nil, fmt.Errorf("parse fleet list: %w", err)
	}

	var rows []FleetRow
	for _, f := range list.Items {
		rows = append(rows, FleetRow{
			Name:     f.Metadata.Name,
			Template: f.Spec.TemplateRef,
			Ready:    f.Status.ReadyCount,
			Total:    f.Spec.Count,
			Zones:    strings.Join(f.Spec.Zones, ","),
		})
	}
	return rows, nil
}

func (c *Client) ScaleFleet(name, count string) error {
	// Validate count is a positive integer to prevent JSON injection
	var n int
	if _, err := fmt.Sscanf(count, "%d", &n); err != nil || n < 0 {
		return fmt.Errorf("invalid count %q: must be a non-negative integer", count)
	}
	patch := fmt.Sprintf(`{"spec":{"count":%d}}`, n)
	_, err := c.kubectl("patch", "decoyfleet", name, "--type=merge", "-p", patch)
	return err
}

func (c *Client) RotateFleet(name string) error {
	patch := fmt.Sprintf(`{"metadata":{"annotations":{"cicdecoy.io/rotate":"%d"}}}`, time.Now().Unix())
	_, err := c.kubectl("patch", "decoyfleet", name, "--type=merge", "-p", patch)
	return err
}

func (c *Client) FleetDetail(name string) (interface{}, error) {
	out, err := c.kubectl("get", "decoyfleet", name, "-o", "json")
	if err != nil {
		return nil, err
	}
	var detail interface{}
	if err := json.Unmarshal(out, &detail); err != nil {
		return nil, fmt.Errorf("parse fleet detail: %w", err)
	}
	return detail, nil
}

func (c *Client) ListProfiles() ([]ProfileRow, error) {
	out, err := c.kubectl("get", "decoyprofiles", "--all-namespaces", "-o", "json")
	if err != nil {
		return nil, err
	}
	var list struct {
		Items []struct {
			Metadata struct{ Name string } `json:"metadata"`
			Spec     struct {
				OS       struct{ Family, Distro string } `json:"os"`
				Packages []interface{}                    `json:"packages"`
				Users    []interface{}                    `json:"users"`
			} `json:"spec"`
		} `json:"items"`
	}
	if err := json.Unmarshal(out, &list); err != nil {
		return nil, fmt.Errorf("parse profile list: %w", err)
	}

	var rows []ProfileRow
	for _, p := range list.Items {
		rows = append(rows, ProfileRow{
			Name:     p.Metadata.Name,
			OS:       p.Spec.OS.Family,
			Distro:   p.Spec.OS.Distro,
			Packages: len(p.Spec.Packages),
			Users:    len(p.Spec.Users),
		})
	}
	return rows, nil
}

func (c *Client) GetProfile(name string) (interface{}, error) {
	out, err := c.kubectl("get", "decoyprofile", name, "-o", "json")
	if err != nil {
		return nil, err
	}
	var detail interface{}
	if err := json.Unmarshal(out, &detail); err != nil {
		return nil, fmt.Errorf("parse profile detail: %w", err)
	}
	return detail, nil
}

func (c *Client) RunFidelityTests(docs []DecoyResource) error {
	// Deploy to staging, run tests, report
	fmt.Println("  (fidelity testing not yet implemented — requires staging cluster)")
	return nil
}

// ── Service Discovery ─────────────────────────────────

func (c *Client) DiscoverNATSURL() (string, error) {
	out, err := c.kubectl("get", "svc", "-l", "app.kubernetes.io/component=nats",
		"-o", "jsonpath={.items[0].metadata.name}")
	if err != nil || strings.TrimSpace(string(out)) == "" {
		return "", fmt.Errorf("NATS service not found")
	}
	return fmt.Sprintf("nats://%s:4222", strings.TrimSpace(string(out))), nil
}

func (c *Client) DiscoverDBDSN() (string, error) {
	// Read DSN from the db-credentials secret
	out, err := c.kubectl("get", "secret", "-l", "app.kubernetes.io/part-of=cicdecoy",
		"-o", "jsonpath={.items[0].data.dsn}")
	if err != nil || strings.TrimSpace(string(out)) == "" {
		return "", fmt.Errorf("DB credentials secret not found")
	}
	// base64 decode
	decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(out)))
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(decoded)), nil
}

// Types re-exported for cmd package
type FleetRow struct {
	Name     string `json:"name"`
	Template string `json:"template"`
	Ready    string `json:"ready"`
	Total    int    `json:"total"`
	Zones    string `json:"zones"`
	Age      string `json:"age"`
}

type ProfileRow struct {
	Name     string `json:"name"`
	OS       string `json:"os"`
	Distro   string `json:"distro"`
	Packages int    `json:"packages"`
	Users    int    `json:"users"`
}
