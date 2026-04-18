package output

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"time"
)

// SplunkConfig holds configuration for Splunk HEC output.
type SplunkConfig struct {
	Endpoint      string // "https://splunk:8088"
	Token         string // HEC token
	Index         string // Target index
	Source        string // Source identifier
	TLSSkipVerify bool
}

type SplunkHECSink struct {
	cfg    SplunkConfig
	client *http.Client
	url    string
	logger *slog.Logger
}

func NewSplunkHEC(cfg SplunkConfig, logger *slog.Logger) (*SplunkHECSink, error) {
	if cfg.Endpoint == "" {
		return nil, fmt.Errorf("splunk endpoint required")
	}
	if cfg.Token == "" {
		return nil, fmt.Errorf("splunk HEC token required")
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

	return &SplunkHECSink{
		cfg:    cfg,
		client: client,
		url:    cfg.Endpoint + "/services/collector/event",
		logger: logger.With("sink", "splunk_hec"),
	}, nil
}

func (s *SplunkHECSink) Send(records []Record) []Result {
	results := make([]Result, len(records))

	// Splunk HEC supports batched events in a single POST.
	// Each event is a JSON object on its own line (no array wrapper).
	var buf bytes.Buffer
	validIndices := []int{}

	for i, rec := range records {
		hecEvent := map[string]interface{}{
			"event":      json.RawMessage(rec.Data),
			"sourcetype": "cicdecoy:raw",
			"source":     s.cfg.Source,
			"index":      s.cfg.Index,
		}

		payload, err := json.Marshal(hecEvent)
		if err != nil {
			results[i] = Result{NATSMsg: rec.NATSMsg, Err: fmt.Errorf("marshal HEC event: %w", err)}
			continue
		}

		buf.Write(payload)
		buf.WriteByte('\n')
		validIndices = append(validIndices, i)
	}

	if len(validIndices) == 0 {
		return results
	}

	// Send the batch
	req, err := http.NewRequest("POST", s.url, &buf)
	if err != nil {
		for _, idx := range validIndices {
			results[idx] = Result{NATSMsg: records[idx].NATSMsg, Err: err}
		}
		return results
	}

	req.Header.Set("Authorization", "Splunk "+s.cfg.Token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := s.client.Do(req)
	if err != nil {
		for _, idx := range validIndices {
			results[idx] = Result{NATSMsg: records[idx].NATSMsg, Err: err}
		}
		return results
	}
	defer resp.Body.Close()
	io.ReadAll(resp.Body) // drain

	if resp.StatusCode >= 400 {
		sendErr := fmt.Errorf("splunk HEC returned %d", resp.StatusCode)
		s.logger.Warn("splunk HEC error", "status", resp.StatusCode)
		for _, idx := range validIndices {
			results[idx] = Result{NATSMsg: records[idx].NATSMsg, Err: sendErr}
		}
		return results
	}

	// Splunk HEC batch is all-or-nothing — if it accepted the POST,
	// all events in the batch were ingested.
	for _, idx := range validIndices {
		results[idx] = Result{NATSMsg: records[idx].NATSMsg, Err: nil}
	}

	return results
}

func (s *SplunkHECSink) Close() error {
	s.client.CloseIdleConnections()
	return nil
}
