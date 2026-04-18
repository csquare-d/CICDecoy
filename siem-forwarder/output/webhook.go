package output

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"time"
)

// WebhookConfig holds configuration for the generic webhook output.
// This is the escape hatch — any SIEM or system that accepts HTTP
// POST with JSON/text bodies can be targeted here.
type WebhookConfig struct {
	URL           string
	Headers       map[string]string // Additional headers (e.g. auth tokens)
	TLSSkipVerify bool
}

type WebhookSink struct {
	cfg    WebhookConfig
	client *http.Client
	logger *slog.Logger
}

func NewWebhook(cfg WebhookConfig, logger *slog.Logger) (*WebhookSink, error) {
	if cfg.URL == "" {
		return nil, fmt.Errorf("webhook URL required")
	}

	client := &http.Client{
		Timeout: 15 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig:     &tls.Config{InsecureSkipVerify: cfg.TLSSkipVerify},
			MaxIdleConns:        10,
			MaxIdleConnsPerHost: 10,
			IdleConnTimeout:     60 * time.Second,
		},
	}

	return &WebhookSink{
		cfg:    cfg,
		client: client,
		logger: logger.With("sink", "webhook"),
	}, nil
}

// Send delivers each record as an individual HTTP POST.
// Unlike Splunk HEC and Elasticsearch which have native batch APIs,
// generic webhooks don't have a standard batching mechanism.
// For high-throughput scenarios, consider using Splunk HEC or
// Elasticsearch directly instead of the webhook adapter.
func (w *WebhookSink) Send(records []Record) []Result {
	results := make([]Result, len(records))

	for i, rec := range records {
		req, err := http.NewRequest("POST", w.cfg.URL, bytes.NewReader(rec.Data))
		if err != nil {
			results[i] = Result{NATSMsg: rec.NATSMsg, Err: err}
			continue
		}

		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("User-Agent", "cicdecoy-siem-forwarder/1.0")

		// Apply custom headers (auth tokens, API keys, etc.)
		for k, v := range w.cfg.Headers {
			req.Header.Set(k, v)
		}

		resp, err := w.client.Do(req)
		if err != nil {
			results[i] = Result{NATSMsg: rec.NATSMsg, Err: err}
			continue
		}
		io.ReadAll(resp.Body)
		resp.Body.Close()

		if resp.StatusCode >= 400 {
			results[i] = Result{
				NATSMsg: rec.NATSMsg,
				Err:     fmt.Errorf("webhook returned %d", resp.StatusCode),
			}
			continue
		}

		results[i] = Result{NATSMsg: rec.NATSMsg, Err: nil}
	}

	return results
}

func (w *WebhookSink) Close() error {
	w.client.CloseIdleConnections()
	return nil
}
