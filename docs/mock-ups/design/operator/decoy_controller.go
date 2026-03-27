// CI/CDecoy — Kubernetes Operator
// operator/src/controllers/decoy_controller.go
//
// Reconciles Decoy Custom Resources into running pods on the k3s cluster.
// Watches for Decoy, DecoyFleet, and HoneyToken CRDs and ensures the
// actual cluster state matches the desired deception posture.
//
// Built with controller-runtime (kubebuilder pattern).

package controllers

import (
	"context"
	"fmt"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	deceptionv1 "cicdecoy.io/operator/api/v1alpha1"
)

// ─────────────────────────────────────────────────────────
//  CRD Type Definitions (api/v1alpha1/decoy_types.go)
// ─────────────────────────────────────────────────────────

// DecoySpec defines the desired state of a Decoy.
// This maps directly to the YAML manifest schema.
type DecoySpec struct {
	Service        ServiceSpec        `json:"service"`
	Fidelity       FidelitySpec       `json:"fidelity"`
	Identity       IdentitySpec       `json:"identity"`
	Authentication AuthSpec           `json:"authentication"`
	Filesystem     FilesystemSpec     `json:"filesystem,omitempty"`
	Telemetry      TelemetrySpec      `json:"telemetry,omitempty"`
	Resources      ResourceSpec       `json:"resources,omitempty"`
	Lifecycle      LifecycleSpec      `json:"lifecycle,omitempty"`
	NetworkBehavior NetworkBehaviorSpec `json:"networkBehavior,omitempty"`
}

type ServiceSpec struct {
	Type           string            `json:"type"` // ssh, http, smb, mysql, etc.
	Port           int32             `json:"port"`
	AdditionalPorts []AdditionalPort `json:"additionalPorts,omitempty"`
}

type AdditionalPort struct {
	Port int32  `json:"port"`
	Type string `json:"type"`
}

type FidelitySpec struct {
	Tier     int           `json:"tier"` // 1, 2, or 3
	Scripted *ScriptedSpec `json:"scripted,omitempty"`
	Adaptive *AdaptiveSpec `json:"adaptive,omitempty"`
}

type ScriptedSpec struct {
	ResponseSet     string           `json:"responseSet,omitempty"`
	CustomResponses []CustomResponse `json:"customResponses,omitempty"`
}

type CustomResponse struct {
	Match    string `json:"match"`
	Response string `json:"response"`
}

type AdaptiveSpec struct {
	ProfileRef      string         `json:"profileRef"`
	InferenceConfig InferenceConf  `json:"inferenceConfig,omitempty"`
	FastPath        FastPathSpec   `json:"fastPath,omitempty"`
	Guardrails      GuardrailSpec  `json:"guardrails,omitempty"`
}

type InferenceConf struct {
	MaxSessionTokens int     `json:"maxSessionTokens,omitempty"`
	Temperature      float64 `json:"temperature,omitempty"`
	CacheDeterministic bool  `json:"cacheDeterministic,omitempty"`
}

type FastPathSpec struct {
	Enabled  bool             `json:"enabled"`
	Commands []FastPathRule   `json:"commands,omitempty"`
}

type FastPathRule struct {
	Match  string `json:"match"`
	Source string `json:"source"`
}

type GuardrailSpec struct {
	PreventRealCommands bool     `json:"preventRealCommands"`
	FilterPatterns      []string `json:"filterPatterns,omitempty"`
	MaxResponseLines    int      `json:"maxResponseLines,omitempty"`
	DisallowedPaths     []string `json:"disallowedPaths,omitempty"`
}

type IdentitySpec struct {
	Hostname    string        `json:"hostname"`
	Domain      string        `json:"domain,omitempty"`
	OS          OSSpec        `json:"os"`
	Fingerprint FingerprintSpec `json:"fingerprint,omitempty"`
}

type OSSpec struct {
	Family       string `json:"family"` // linux, windows
	Distribution string `json:"distribution,omitempty"`
	Version      string `json:"version,omitempty"`
	Kernel       string `json:"kernel,omitempty"`
}

type FingerprintSpec struct {
	TCPWindowSize int    `json:"tcpWindowSize,omitempty"`
	TTL           int    `json:"ttl,omitempty"`
	SSHBanner     string `json:"sshBanner,omitempty"`
	HTTPServer    string `json:"httpServer,omitempty"`
}

type AuthSpec struct {
	Mode        string           `json:"mode"` // open, selective, realistic, closed
	Credentials []CredentialSpec `json:"credentials,omitempty"`
}

type CredentialSpec struct {
	Username string `json:"username"`
	Password string `json:"password"`
	Shell    string `json:"shell,omitempty"`
	UID      int    `json:"uid,omitempty"`
	Home     string `json:"home,omitempty"`
}

type FilesystemSpec struct {
	Base     string        `json:"base,omitempty"`
	Overlays []OverlaySpec `json:"overlays,omitempty"`
}

type OverlaySpec struct {
	Type       string `json:"type"` // profile, inline, honeytoken
	ProfileRef string `json:"profileRef,omitempty"`
}

type TelemetrySpec struct {
	SessionCapture SessionCaptureSpec `json:"sessionCapture,omitempty"`
	Exporters      []ExporterSpec     `json:"exporters,omitempty"`
}

type SessionCaptureSpec struct {
	FullTranscript   bool `json:"fullTranscript,omitempty"`
	KeystrokeTimings bool `json:"keystrokeTimings,omitempty"`
	FileUploads      bool `json:"fileUploads,omitempty"`
}

type ExporterSpec struct {
	Type     string `json:"type"` // nats, otel
	Endpoint string `json:"endpoint"`
	Subject  string `json:"subject,omitempty"`
}

type ResourceSpec struct {
	Requests corev1.ResourceList `json:"requests,omitempty"`
	Limits   corev1.ResourceList `json:"limits,omitempty"`
}

type LifecycleSpec struct {
	Rotation    RotationSpec    `json:"rotation,omitempty"`
	HealthCheck HealthCheckSpec `json:"healthCheck,omitempty"`
}

type RotationSpec struct {
	Enabled  bool   `json:"enabled,omitempty"`
	Interval string `json:"interval,omitempty"` // e.g., "168h"
	Strategy string `json:"strategy,omitempty"` // gradual, immediate
}

type HealthCheckSpec struct {
	Enabled               bool   `json:"enabled,omitempty"`
	Interval              string `json:"interval,omitempty"`
	FingerprintValidation bool   `json:"fingerprintValidation,omitempty"`
}

type NetworkBehaviorSpec struct {
	BeaconTraffic   BeaconSpec       `json:"beaconTraffic,omitempty"`
	Discoverability DiscoverSpec     `json:"discoverability,omitempty"`
}

type BeaconSpec struct {
	Enabled bool          `json:"enabled,omitempty"`
	Targets []BeaconTarget `json:"targets,omitempty"`
}

type BeaconTarget struct {
	Host     string `json:"host"`
	Port     int32  `json:"port"`
	Protocol string `json:"protocol"`
	Interval string `json:"interval"`
}

type DiscoverSpec struct {
	ARPRespond  bool `json:"arpRespond,omitempty"`
	PingRespond bool `json:"pingRespond,omitempty"`
}

// DecoyStatus defines the observed state of a Decoy.
type DecoyStatus struct {
	Phase           string      `json:"phase"`           // Pending, Running, Degraded, Rotating
	Ready           bool        `json:"ready"`
	PodName         string      `json:"podName,omitempty"`
	PodIP           string      `json:"podIP,omitempty"`
	LastHealthCheck metav1.Time `json:"lastHealthCheck,omitempty"`
	SessionCount    int64       `json:"sessionCount,omitempty"`
	LastRotation    metav1.Time `json:"lastRotation,omitempty"`
	Conditions      []metav1.Condition `json:"conditions,omitempty"`
}


// ─────────────────────────────────────────────────────────
//  Reconciler
// ─────────────────────────────────────────────────────────

// DecoyReconciler reconciles Decoy CRDs into running pods.
type DecoyReconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

// Reconcile is the main control loop. It's called whenever a Decoy
// resource is created, updated, or deleted.
func (r *DecoyReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx)

	// Fetch the Decoy resource
	var decoy deceptionv1.Decoy
	if err := r.Get(ctx, req.NamespacedName, &decoy); err != nil {
		if errors.IsNotFound(err) {
			// Decoy was deleted — cleanup handled by ownerReferences
			logger.Info("Decoy deleted, cleanup via ownerReferences")
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, err
	}

	logger.Info("Reconciling Decoy",
		"name", decoy.Name,
		"tier", decoy.Spec.Fidelity.Tier,
		"service", decoy.Spec.Service.Type,
	)

	// ── Step 1: Validate the Decoy spec ──
	if err := r.validateDecoy(&decoy); err != nil {
		logger.Error(err, "Validation failed")
		return r.updateStatus(ctx, &decoy, "Failed", false, err.Error())
	}

	// ── Step 2: Ensure ConfigMap exists with decoy config ──
	if err := r.reconcileConfigMap(ctx, &decoy); err != nil {
		logger.Error(err, "Failed to reconcile ConfigMap")
		return ctrl.Result{RequeueAfter: 30 * time.Second}, err
	}

	// ── Step 3: Ensure Pod/Deployment exists ──
	if err := r.reconcileDeployment(ctx, &decoy); err != nil {
		logger.Error(err, "Failed to reconcile Deployment")
		return ctrl.Result{RequeueAfter: 30 * time.Second}, err
	}

	// ── Step 4: Ensure Service exists (for port exposure) ──
	if err := r.reconcileService(ctx, &decoy); err != nil {
		logger.Error(err, "Failed to reconcile Service")
		return ctrl.Result{RequeueAfter: 30 * time.Second}, err
	}

	// ── Step 5: Check rotation schedule ──
	if decoy.Spec.Lifecycle.Rotation.Enabled {
		if needsRotation, _ := r.checkRotation(&decoy); needsRotation {
			logger.Info("Decoy needs rotation", "name", decoy.Name)
			return r.performRotation(ctx, &decoy)
		}
	}

	// ── Step 6: Update status ──
	return r.updateStatus(ctx, &decoy, "Running", true, "")
}

// ─────────────────────────────────────────────────────────
//  Validation
// ─────────────────────────────────────────────────────────

func (r *DecoyReconciler) validateDecoy(decoy *deceptionv1.Decoy) error {
	spec := decoy.Spec

	// Tier validation
	if spec.Fidelity.Tier < 1 || spec.Fidelity.Tier > 3 {
		return fmt.Errorf("invalid fidelity tier: %d (must be 1-3)", spec.Fidelity.Tier)
	}

	// Tier 3 requires adaptive config
	if spec.Fidelity.Tier == 3 && spec.Fidelity.Adaptive == nil {
		return fmt.Errorf("tier 3 decoys require adaptive configuration")
	}

	// Tier 3 requires guardrails
	if spec.Fidelity.Tier == 3 {
		if spec.Fidelity.Adaptive.Guardrails.FilterPatterns == nil ||
			len(spec.Fidelity.Adaptive.Guardrails.FilterPatterns) == 0 {
			return fmt.Errorf("tier 3 decoys require at least one guardrail filter pattern")
		}
	}

	// Port validation
	if spec.Service.Port < 1 || spec.Service.Port > 65535 {
		return fmt.Errorf("invalid port: %d", spec.Service.Port)
	}

	// OS/fingerprint coherence
	if spec.Identity.OS.Family == "linux" && spec.Identity.Fingerprint.TTL != 0 {
		if spec.Identity.Fingerprint.TTL != 64 {
			// Linux default TTL is 64; warn but don't block
			// (could be intentionally deceptive)
		}
	}

	return nil
}

// ─────────────────────────────────────────────────────────
//  ConfigMap — Decoy configuration mounted into pod
// ─────────────────────────────────────────────────────────

func (r *DecoyReconciler) reconcileConfigMap(ctx context.Context, decoy *deceptionv1.Decoy) error {
	configMapName := fmt.Sprintf("decoy-config-%s", decoy.Name)

	// Serialize the decoy spec as YAML for the container to consume
	configData, err := serializeDecoyConfig(decoy)
	if err != nil {
		return fmt.Errorf("failed to serialize config: %w", err)
	}

	desired := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      configMapName,
			Namespace: decoy.Namespace,
			Labels:    decoyLabels(decoy),
		},
		Data: map[string]string{
			"decoy.yaml": configData,
		},
	}

	// Set owner reference for garbage collection
	ctrl.SetControllerReference(decoy, desired, r.Scheme)

	// Create or update
	existing := &corev1.ConfigMap{}
	err = r.Get(ctx, types.NamespacedName{Name: configMapName, Namespace: decoy.Namespace}, existing)
	if errors.IsNotFound(err) {
		return r.Create(ctx, desired)
	} else if err != nil {
		return err
	}

	existing.Data = desired.Data
	return r.Update(ctx, existing)
}

// ─────────────────────────────────────────────────────────
//  Deployment — The actual decoy pod
// ─────────────────────────────────────────────────────────

func (r *DecoyReconciler) reconcileDeployment(ctx context.Context, decoy *deceptionv1.Decoy) error {
	deploymentName := fmt.Sprintf("decoy-%s", decoy.Name)
	replicas := int32(1)

	// Select container image based on service type
	image := r.imageForServiceType(decoy.Spec.Service.Type)

	// Build resource requirements based on tier
	resources := r.resourcesForTier(decoy)

	// Container ports
	ports := []corev1.ContainerPort{
		{
			Name:          "service",
			ContainerPort: decoy.Spec.Service.Port,
			Protocol:      corev1.ProtocolTCP,
		},
	}
	for _, ap := range decoy.Spec.Service.AdditionalPorts {
		ports = append(ports, corev1.ContainerPort{
			Name:          fmt.Sprintf("svc-%d", ap.Port),
			ContainerPort: ap.Port,
			Protocol:      corev1.ProtocolTCP,
		})
	}

	// Environment variables
	env := []corev1.EnvVar{
		{Name: "DECOY_CONFIG", Value: "/etc/cicdecoy/decoy.yaml"},
		{Name: "DECOY_NAME", Value: decoy.Name},
		{Name: "DECOY_TIER", Value: fmt.Sprintf("%d", decoy.Spec.Fidelity.Tier)},
		{Name: "DECOY_HOSTNAME", Value: decoy.Spec.Identity.Hostname},
	}

	// Add inference endpoint for tier 3
	if decoy.Spec.Fidelity.Tier == 3 {
		endpoint := "http://inference-gateway.cicdecoy-system:8000"
		if decoy.Spec.Fidelity.Adaptive != nil {
			env = append(env, corev1.EnvVar{
				Name:  "INFERENCE_ENDPOINT",
				Value: endpoint,
			})
			env = append(env, corev1.EnvVar{
				Name:  "DECOY_PROFILE",
				Value: decoy.Spec.Fidelity.Adaptive.ProfileRef,
			})
		}
	}

	// Add NATS endpoint for telemetry
	for _, exporter := range decoy.Spec.Telemetry.Exporters {
		if exporter.Type == "nats" {
			env = append(env, corev1.EnvVar{
				Name:  "NATS_ENDPOINT",
				Value: exporter.Endpoint,
			})
			env = append(env, corev1.EnvVar{
				Name:  "NATS_SUBJECT",
				Value: exporter.Subject,
			})
		}
	}

	desired := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:      deploymentName,
			Namespace: decoy.Namespace,
			Labels:    decoyLabels(decoy),
		},
		Spec: appsv1.DeploymentSpec{
			Replicas: &replicas,
			Selector: &metav1.LabelSelector{
				MatchLabels: decoyLabels(decoy),
			},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels:      decoyLabels(decoy),
					Annotations: decoyAnnotations(decoy),
				},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{
						{
							Name:      "decoy",
							Image:     image,
							Ports:     ports,
							Env:       env,
							Resources: resources,
							VolumeMounts: []corev1.VolumeMount{
								{
									Name:      "config",
									MountPath: "/etc/cicdecoy",
									ReadOnly:  true,
								},
							},
							// Health check — verify the decoy service is responding
							ReadinessProbe: &corev1.Probe{
								ProbeHandler: corev1.ProbeHandler{
									TCPSocket: &corev1.TCPSocketAction{
										Port: intstr.FromInt(int(decoy.Spec.Service.Port)),
									},
								},
								InitialDelaySeconds: 5,
								PeriodSeconds:       10,
							},
							LivenessProbe: &corev1.Probe{
								ProbeHandler: corev1.ProbeHandler{
									TCPSocket: &corev1.TCPSocketAction{
										Port: intstr.FromInt(int(decoy.Spec.Service.Port)),
									},
								},
								InitialDelaySeconds: 15,
								PeriodSeconds:       30,
							},
						},
					},
					Volumes: []corev1.Volume{
						{
							Name: "config",
							VolumeSource: corev1.VolumeSource{
								ConfigMap: &corev1.ConfigMapVolumeSource{
									LocalObjectReference: corev1.LocalObjectReference{
										Name: fmt.Sprintf("decoy-config-%s", decoy.Name),
									},
								},
							},
						},
					},
					// Security context — restrict decoy container privileges
					SecurityContext: &corev1.PodSecurityContext{
						RunAsNonRoot: boolPtr(true),
						RunAsUser:    int64Ptr(1000),
					},
				},
			},
		},
	}

	ctrl.SetControllerReference(decoy, desired, r.Scheme)

	// Create or update
	existing := &appsv1.Deployment{}
	err := r.Get(ctx, types.NamespacedName{Name: deploymentName, Namespace: decoy.Namespace}, existing)
	if errors.IsNotFound(err) {
		return r.Create(ctx, desired)
	} else if err != nil {
		return err
	}

	existing.Spec = desired.Spec
	return r.Update(ctx, existing)
}

// ─────────────────────────────────────────────────────────
//  Service — Expose decoy ports
// ─────────────────────────────────────────────────────────

func (r *DecoyReconciler) reconcileService(ctx context.Context, decoy *deceptionv1.Decoy) error {
	serviceName := fmt.Sprintf("decoy-svc-%s", decoy.Name)

	ports := []corev1.ServicePort{
		{
			Name:       "service",
			Port:       decoy.Spec.Service.Port,
			TargetPort: intstr.FromInt(int(decoy.Spec.Service.Port)),
			Protocol:   corev1.ProtocolTCP,
		},
	}
	for _, ap := range decoy.Spec.Service.AdditionalPorts {
		ports = append(ports, corev1.ServicePort{
			Name:       fmt.Sprintf("svc-%d", ap.Port),
			Port:       ap.Port,
			TargetPort: intstr.FromInt(int(ap.Port)),
			Protocol:   corev1.ProtocolTCP,
		})
	}

	desired := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      serviceName,
			Namespace: decoy.Namespace,
			Labels:    decoyLabels(decoy),
		},
		Spec: corev1.ServiceSpec{
			Selector: decoyLabels(decoy),
			Ports:    ports,
			Type:     corev1.ServiceTypeClusterIP,
		},
	}

	ctrl.SetControllerReference(decoy, desired, r.Scheme)

	existing := &corev1.Service{}
	err := r.Get(ctx, types.NamespacedName{Name: serviceName, Namespace: decoy.Namespace}, existing)
	if errors.IsNotFound(err) {
		return r.Create(ctx, desired)
	} else if err != nil {
		return err
	}

	existing.Spec.Ports = desired.Spec.Ports
	return r.Update(ctx, existing)
}

// ─────────────────────────────────────────────────────────
//  Rotation — Periodic identity refresh
// ─────────────────────────────────────────────────────────

func (r *DecoyReconciler) checkRotation(decoy *deceptionv1.Decoy) (bool, error) {
	if !decoy.Spec.Lifecycle.Rotation.Enabled {
		return false, nil
	}

	interval, err := time.ParseDuration(decoy.Spec.Lifecycle.Rotation.Interval)
	if err != nil {
		return false, fmt.Errorf("invalid rotation interval: %w", err)
	}

	lastRotation := decoy.Status.LastRotation.Time
	if lastRotation.IsZero() {
		// Never rotated — use creation time
		lastRotation = decoy.CreationTimestamp.Time
	}

	return time.Since(lastRotation) > interval, nil
}

func (r *DecoyReconciler) performRotation(ctx context.Context, decoy *deceptionv1.Decoy) (ctrl.Result, error) {
	logger := log.FromContext(ctx)

	strategy := decoy.Spec.Lifecycle.Rotation.Strategy
	logger.Info("Performing rotation",
		"name", decoy.Name,
		"strategy", strategy,
	)

	if strategy == "immediate" {
		// Delete the deployment — reconciler will recreate with new identity
		deploymentName := fmt.Sprintf("decoy-%s", decoy.Name)
		deployment := &appsv1.Deployment{}
		if err := r.Get(ctx, types.NamespacedName{
			Name: deploymentName, Namespace: decoy.Namespace,
		}, deployment); err == nil {
			if err := r.Delete(ctx, deployment); err != nil {
				return ctrl.Result{}, err
			}
		}
	} else {
		// Gradual: trigger a rolling restart by updating an annotation
		deploymentName := fmt.Sprintf("decoy-%s", decoy.Name)
		deployment := &appsv1.Deployment{}
		if err := r.Get(ctx, types.NamespacedName{
			Name: deploymentName, Namespace: decoy.Namespace,
		}, deployment); err == nil {
			if deployment.Spec.Template.Annotations == nil {
				deployment.Spec.Template.Annotations = make(map[string]string)
			}
			deployment.Spec.Template.Annotations["cicdecoy.io/rotated-at"] =
				time.Now().Format(time.RFC3339)
			if err := r.Update(ctx, deployment); err != nil {
				return ctrl.Result{}, err
			}
		}
	}

	// Update rotation timestamp
	decoy.Status.LastRotation = metav1.Now()
	decoy.Status.Phase = "Rotating"
	if err := r.Status().Update(ctx, decoy); err != nil {
		return ctrl.Result{}, err
	}

	return ctrl.Result{RequeueAfter: 30 * time.Second}, nil
}

// ─────────────────────────────────────────────────────────
//  Helpers
// ─────────────────────────────────────────────────────────

func (r *DecoyReconciler) imageForServiceType(serviceType string) string {
	imageMap := map[string]string{
		"ssh":      "cicdecoy/ssh-decoy:latest",
		"http":     "cicdecoy/http-decoy:latest",
		"https":    "cicdecoy/http-decoy:latest",
		"smb":      "cicdecoy/smb-decoy:latest",
		"mysql":    "cicdecoy/mysql-decoy:latest",
		"postgres": "cicdecoy/mysql-decoy:latest", // Shared DB decoy image
		"rdp":      "cicdecoy/rdp-decoy:latest",
		"ftp":      "cicdecoy/ftp-decoy:latest",
		"dns":      "cicdecoy/dns-decoy:latest",
	}
	if img, ok := imageMap[serviceType]; ok {
		return img
	}
	return "cicdecoy/generic-decoy:latest"
}

func (r *DecoyReconciler) resourcesForTier(decoy *deceptionv1.Decoy) corev1.ResourceRequirements {
	// Default resources by tier
	defaults := map[int]corev1.ResourceRequirements{
		1: {
			Requests: corev1.ResourceList{
				corev1.ResourceCPU:    resource.MustParse("50m"),
				corev1.ResourceMemory: resource.MustParse("32Mi"),
			},
			Limits: corev1.ResourceList{
				corev1.ResourceCPU:    resource.MustParse("100m"),
				corev1.ResourceMemory: resource.MustParse("64Mi"),
			},
		},
		2: {
			Requests: corev1.ResourceList{
				corev1.ResourceCPU:    resource.MustParse("100m"),
				corev1.ResourceMemory: resource.MustParse("128Mi"),
			},
			Limits: corev1.ResourceList{
				corev1.ResourceCPU:    resource.MustParse("500m"),
				corev1.ResourceMemory: resource.MustParse("256Mi"),
			},
		},
		3: {
			Requests: corev1.ResourceList{
				corev1.ResourceCPU:    resource.MustParse("200m"),
				corev1.ResourceMemory: resource.MustParse("256Mi"),
			},
			Limits: corev1.ResourceList{
				corev1.ResourceCPU:    resource.MustParse("1000m"),
				corev1.ResourceMemory: resource.MustParse("1Gi"),
			},
		},
	}

	if res, ok := defaults[decoy.Spec.Fidelity.Tier]; ok {
		return res
	}
	return defaults[1]
}

func (r *DecoyReconciler) updateStatus(
	ctx context.Context,
	decoy *deceptionv1.Decoy,
	phase string,
	ready bool,
	message string,
) (ctrl.Result, error) {
	decoy.Status.Phase = phase
	decoy.Status.Ready = ready

	if err := r.Status().Update(ctx, decoy); err != nil {
		return ctrl.Result{}, err
	}

	// Requeue for periodic health checks
	return ctrl.Result{RequeueAfter: 60 * time.Second}, nil
}

func decoyLabels(decoy *deceptionv1.Decoy) map[string]string {
	return map[string]string{
		"app.kubernetes.io/name":       "cicdecoy",
		"app.kubernetes.io/component":  "decoy",
		"app.kubernetes.io/instance":   decoy.Name,
		"cicdecoy.io/tier":            fmt.Sprintf("%d", decoy.Spec.Fidelity.Tier),
		"cicdecoy.io/service-type":    decoy.Spec.Service.Type,
	}
}

func decoyAnnotations(decoy *deceptionv1.Decoy) map[string]string {
	return map[string]string{
		"cicdecoy.io/hostname": decoy.Spec.Identity.Hostname,
		"cicdecoy.io/domain":   decoy.Spec.Identity.Domain,
	}
}

func serializeDecoyConfig(decoy *deceptionv1.Decoy) (string, error) {
	// In production, use a proper YAML serializer
	// For prototype, marshal to JSON then YAML
	return fmt.Sprintf("# Auto-generated by CI/CDecoy operator\n# Decoy: %s\n", decoy.Name), nil
}

func boolPtr(b bool) *bool       { return &b }
func int64Ptr(i int64) *int64    { return &i }

// ─────────────────────────────────────────────────────────
//  Setup — Register with controller-runtime
// ─────────────────────────────────────────────────────────

func (r *DecoyReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&deceptionv1.Decoy{}).
		Owns(&appsv1.Deployment{}).
		Owns(&corev1.Service{}).
		Owns(&corev1.ConfigMap{}).
		Complete(r)
}
