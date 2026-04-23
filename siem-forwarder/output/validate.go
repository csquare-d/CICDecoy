package output

import (
	"fmt"
	"net"
	"net/url"
	"strings"
)

// ValidateEndpointURL checks that a URL does not point to a private,
// loopback, or link-local address.  This prevents SSRF attacks where
// a misconfigured endpoint could reach internal services.
func ValidateEndpointURL(rawURL string) error {
	u, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("invalid URL: %w", err)
	}

	host := u.Hostname()
	if host == "" {
		return fmt.Errorf("URL has no host")
	}

	// Reject localhost variants
	lower := strings.ToLower(host)
	if lower == "localhost" || lower == "0.0.0.0" {
		return fmt.Errorf("endpoint must not target localhost (%s)", host)
	}

	// Reject well-known metadata endpoints
	if lower == "metadata.google.internal" || lower == "metadata.gcp.internal" {
		return fmt.Errorf("endpoint must not target cloud metadata service (%s)", host)
	}

	// Reject known internal K8s services
	if lower == "kubernetes.default.svc" || lower == "kubernetes.default" ||
		strings.HasSuffix(lower, ".svc.cluster.local") {
		return fmt.Errorf("endpoint must not target Kubernetes internal services (%s)", host)
	}

	// Resolve IP and check against private ranges
	ips, err := net.LookupIP(host)
	if err != nil {
		// DNS resolution failed — allow (might be resolvable later in K8s)
		return nil
	}

	for _, ip := range ips {
		if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
			return fmt.Errorf("endpoint resolves to private/loopback address (%s → %s); "+
				"set ALLOW_PRIVATE_ENDPOINTS=true to override", host, ip)
		}
	}

	return nil
}
