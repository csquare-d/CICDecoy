package output

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"time"
)

// ElasticConfig holds configuration for Elasticsearch output.
type ElasticConfig struct {
	Endpoint      string // "https://elastic:9200"
	Index         string // Index name or pattern
	Username      string // Basic auth
	Password      string
	APIKey        string // Alternative to basic auth
	TLSSkipVerify bool
}

type ElasticsearchSink struct {
	cfg    ElasticConfig
	client *http.Client
	logger *slog.Logger
}

func NewElasticsearch(cfg ElasticConfig, logger *slog.Logger) (*ElasticsearchSink, error) {
	if cfg.Endpoint == "" {
		return nil, fmt.Errorf("elasticsearch endpoint required")
	}
	if cfg.Index == "" {
		cfg.Index = "cicdecoy-raw"
	}

	if os.Getenv("ALLOW_PRIVATE_ENDPOINTS") == "" {
		if err := ValidateEndpointURL(cfg.Endpoint); err != nil {
			return nil, fmt.Errorf("elasticsearch endpoint validation failed: %w", err)
		}
	}

	client := &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig:     &tls.Config{InsecureSkipVerify: cfg.TLSSkipVerify},
			MaxIdleConns:        10,
			MaxIdleConnsPerHost: 10,
			IdleConnTimeout:     60 * time.Second,
		},
	}

	return &ElasticsearchSink{
		cfg:    cfg,
		client: client,
		logger: logger.With("sink", "elasticsearch"),
	}, nil
}

func (e *ElasticsearchSink) Send(records []Record) []Result {
	results := make([]Result, len(records))

	// Use the Elasticsearch Bulk API for efficient batching.
	// Format: action_line\n source_line\n (NDJSON)
	var buf bytes.Buffer
	validIndices := []int{}

	for i, rec := range records {
		// Action line: index into the configured index with auto-generated _id.
		// Use date-based index names for time-series data.
		indexName := fmt.Sprintf("%s-%s", e.cfg.Index, time.Now().UTC().Format("2006.01.02"))
		action := map[string]interface{}{
			"index": map[string]interface{}{
				"_index": indexName,
			},
		}

		actionBytes, err := json.Marshal(action)
		if err != nil {
			results[i] = Result{NATSMsg: rec.NATSMsg, Err: err}
			continue
		}

		buf.Write(actionBytes)
		buf.WriteByte('\n')
		buf.Write(rec.Data)
		buf.WriteByte('\n')
		validIndices = append(validIndices, i)
	}

	if len(validIndices) == 0 {
		return results
	}

	// POST to _bulk endpoint
	url := e.cfg.Endpoint + "/_bulk"
	req, err := http.NewRequest("POST", url, &buf)
	if err != nil {
		for _, idx := range validIndices {
			results[idx] = Result{NATSMsg: records[idx].NATSMsg, Err: err}
		}
		return results
	}

	req.Header.Set("Content-Type", "application/x-ndjson")

	// Auth: API key takes precedence over basic auth
	if e.cfg.APIKey != "" {
		req.Header.Set("Authorization", "ApiKey "+e.cfg.APIKey)
	} else if e.cfg.Username != "" {
		req.SetBasicAuth(e.cfg.Username, e.cfg.Password)
	}

	resp, err := e.client.Do(req)
	if err != nil {
		for _, idx := range validIndices {
			results[idx] = Result{NATSMsg: records[idx].NATSMsg, Err: err}
		}
		return results
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		e.logger.Warn("failed to read elasticsearch response body", "error", err)
		body = []byte("(unreadable)")
	}

	if resp.StatusCode >= 400 {
		sendErr := fmt.Errorf("elasticsearch bulk returned %d", resp.StatusCode)
		e.logger.Warn("elasticsearch bulk error",
			"status", resp.StatusCode,
			"body", truncateStr(string(body), 500),
		)
		for _, idx := range validIndices {
			results[idx] = Result{NATSMsg: records[idx].NATSMsg, Err: sendErr}
		}
		return results
	}

	// Parse bulk response to check for per-item errors.
	var bulkResp struct {
		Errors bool `json:"errors"`
		Items  []struct {
			Index struct {
				Status int    `json:"status"`
				Error  *struct {
					Type   string `json:"type"`
					Reason string `json:"reason"`
				} `json:"error,omitempty"`
			} `json:"index"`
		} `json:"items"`
	}

	if err := json.Unmarshal(body, &bulkResp); err != nil {
		parseErr := fmt.Errorf("failed to parse bulk response: %w", err)
		e.logger.Warn("bulk response parse failed, marking records as errors",
			"error", err,
			"status", resp.StatusCode,
		)
		for _, idx := range validIndices {
			results[idx] = Result{NATSMsg: records[idx].NATSMsg, Err: parseErr}
		}
		return results
	}

	// Map per-item results back to records
	for itemIdx, recIdx := range validIndices {
		if itemIdx < len(bulkResp.Items) {
			item := bulkResp.Items[itemIdx]
			if item.Index.Error != nil {
				results[recIdx] = Result{
					NATSMsg: records[recIdx].NATSMsg,
					Err:     fmt.Errorf("%s: %s", item.Index.Error.Type, item.Index.Error.Reason),
				}
			} else {
				results[recIdx] = Result{NATSMsg: records[recIdx].NATSMsg, Err: nil}
			}
		} else {
			results[recIdx] = Result{NATSMsg: records[recIdx].NATSMsg, Err: nil}
		}
	}

	return results
}

func (e *ElasticsearchSink) Close() error {
	e.client.CloseIdleConnections()
	return nil
}

func truncateStr(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "..."
}
