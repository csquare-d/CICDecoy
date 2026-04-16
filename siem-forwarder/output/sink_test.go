package output

import (
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// ── SplunkHEC Tests ─────────────────────────────────────

func TestNewSplunkHEC_Validation(t *testing.T) {
	logger := testLogger()

	tests := []struct {
		name    string
		cfg     SplunkConfig
		wantErr string
	}{
		{
			name:    "missing endpoint",
			cfg:     SplunkConfig{Token: "tok"},
			wantErr: "splunk endpoint required",
		},
		{
			name:    "missing token",
			cfg:     SplunkConfig{Endpoint: "https://splunk:8088"},
			wantErr: "splunk HEC token required",
		},
		{
			name: "valid config",
			cfg: SplunkConfig{
				Endpoint: "https://splunk:8088",
				Token:    "test-token",
				Index:    "main",
				Source:   "test",
			},
			wantErr: "",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			sink, err := NewSplunkHEC(tc.cfg, logger)
			if tc.wantErr != "" {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				if !strings.Contains(err.Error(), tc.wantErr) {
					t.Errorf("error = %q, want containing %q", err.Error(), tc.wantErr)
				}
			} else {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				if sink == nil {
					t.Fatal("sink should not be nil")
				}
				sink.Close()
			}
		})
	}
}

func TestSplunkHEC_Send(t *testing.T) {
	var mu sync.Mutex
	var receivedBodies []string

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()

		// Verify auth header
		if auth := r.Header.Get("Authorization"); auth != "Splunk test-token-123" {
			t.Errorf("auth header = %q", auth)
		}
		if ct := r.Header.Get("Content-Type"); ct != "application/json" {
			t.Errorf("content-type = %q", ct)
		}
		body, _ := io.ReadAll(r.Body)
		receivedBodies = append(receivedBodies, string(body))
		w.WriteHeader(200)
	}))
	defer server.Close()

	sink, err := NewSplunkHEC(SplunkConfig{
		Endpoint: server.URL,
		Token:    "test-token-123",
		Index:    "cicdecoy",
		Source:   "test",
	}, testLogger())
	if err != nil {
		t.Fatalf("NewSplunkHEC: %v", err)
	}
	defer sink.Close()

	records := []Record{
		{Data: []byte(`{"event_type":"command.exec","source_ip":"10.0.0.1"}`)},
		{Data: []byte(`{"event_type":"auth.success","source_ip":"10.0.0.2"}`)},
	}

	results := sink.Send(records)

	if len(results) != 2 {
		t.Fatalf("expected 2 results, got %d", len(results))
	}
	for i, r := range results {
		if r.Err != nil {
			t.Errorf("result[%d] error = %v", i, r.Err)
		}
	}

	mu.Lock()
	defer mu.Unlock()
	if len(receivedBodies) != 1 {
		t.Fatalf("expected 1 batch POST, got %d", len(receivedBodies))
	}

	// Each line should be a valid HEC event JSON
	lines := strings.Split(strings.TrimSpace(receivedBodies[0]), "\n")
	if len(lines) != 2 {
		t.Fatalf("expected 2 lines in batch, got %d", len(lines))
	}

	for i, line := range lines {
		var hecEvent map[string]interface{}
		if err := json.Unmarshal([]byte(line), &hecEvent); err != nil {
			t.Errorf("line %d is not valid JSON: %v", i, err)
			continue
		}
		if hecEvent["sourcetype"] != "cicdecoy:raw" {
			t.Errorf("line %d sourcetype = %v", i, hecEvent["sourcetype"])
		}
		if hecEvent["index"] != "cicdecoy" {
			t.Errorf("line %d index = %v", i, hecEvent["index"])
		}
	}
}

func TestSplunkHEC_Send_ServerError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(503)
	}))
	defer server.Close()

	sink, err := NewSplunkHEC(SplunkConfig{
		Endpoint: server.URL,
		Token:    "tok",
		Index:    "test",
		Source:   "test",
	}, testLogger())
	if err != nil {
		t.Fatal(err)
	}
	defer sink.Close()

	results := sink.Send([]Record{{Data: []byte(`{}`)}})
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if results[0].Err == nil {
		t.Error("expected error for 503 response")
	}
	if !strings.Contains(results[0].Err.Error(), "503") {
		t.Errorf("error should mention status code, got: %v", results[0].Err)
	}
}

// ── Elasticsearch Tests ─────────────────────────────────

func TestNewElasticsearch_Validation(t *testing.T) {
	logger := testLogger()

	tests := []struct {
		name    string
		cfg     ElasticConfig
		wantErr string
	}{
		{
			name:    "missing endpoint",
			cfg:     ElasticConfig{},
			wantErr: "elasticsearch endpoint required",
		},
		{
			name: "valid config with defaults",
			cfg: ElasticConfig{
				Endpoint: "https://elastic:9200",
			},
			wantErr: "",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			sink, err := NewElasticsearch(tc.cfg, logger)
			if tc.wantErr != "" {
				if err == nil {
					t.Fatal("expected error")
				}
				if !strings.Contains(err.Error(), tc.wantErr) {
					t.Errorf("error = %q, want containing %q", err.Error(), tc.wantErr)
				}
			} else {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				if sink == nil {
					t.Fatal("sink should not be nil")
				}
				sink.Close()
			}
		})
	}
}

func TestElasticsearch_Send(t *testing.T) {
	var mu sync.Mutex
	var receivedBody string
	var receivedAuth string

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()

		receivedAuth = r.Header.Get("Authorization")
		if ct := r.Header.Get("Content-Type"); ct != "application/x-ndjson" {
			t.Errorf("content-type = %q, want application/x-ndjson", ct)
		}
		body, _ := io.ReadAll(r.Body)
		receivedBody = string(body)

		// Return a successful bulk response
		resp := fmt.Sprintf(`{"errors":false,"items":[{"index":{"status":201}},{"index":{"status":201}}]}`)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(200)
		w.Write([]byte(resp))
	}))
	defer server.Close()

	sink, err := NewElasticsearch(ElasticConfig{
		Endpoint: server.URL,
		Index:    "cicdecoy-raw",
		APIKey:   "test-api-key",
	}, testLogger())
	if err != nil {
		t.Fatal(err)
	}
	defer sink.Close()

	records := []Record{
		{Data: []byte(`{"event_type":"command.exec"}`)},
		{Data: []byte(`{"event_type":"auth.success"}`)},
	}

	results := sink.Send(records)

	if len(results) != 2 {
		t.Fatalf("expected 2 results, got %d", len(results))
	}
	for i, r := range results {
		if r.Err != nil {
			t.Errorf("result[%d] error = %v", i, r.Err)
		}
	}

	mu.Lock()
	defer mu.Unlock()

	if receivedAuth != "ApiKey test-api-key" {
		t.Errorf("auth = %q, want 'ApiKey test-api-key'", receivedAuth)
	}

	// Check NDJSON format: alternating action + source lines
	lines := strings.Split(strings.TrimSpace(receivedBody), "\n")
	if len(lines) != 4 {
		t.Fatalf("expected 4 NDJSON lines (2 action + 2 source), got %d", len(lines))
	}
	// First line should be an action
	var action map[string]interface{}
	if err := json.Unmarshal([]byte(lines[0]), &action); err != nil {
		t.Fatalf("first line not valid JSON: %v", err)
	}
	if _, ok := action["index"]; !ok {
		t.Error("first line should be an index action")
	}
}

func TestElasticsearch_Send_PerItemErrors(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := `{"errors":true,"items":[{"index":{"status":201}},{"index":{"status":400,"error":{"type":"mapper_parsing_exception","reason":"bad field"}}}]}`
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(200)
		w.Write([]byte(resp))
	}))
	defer server.Close()

	sink, err := NewElasticsearch(ElasticConfig{
		Endpoint: server.URL,
		Index:    "test",
	}, testLogger())
	if err != nil {
		t.Fatal(err)
	}
	defer sink.Close()

	records := []Record{
		{Data: []byte(`{"ok":true}`)},
		{Data: []byte(`{"bad":true}`)},
	}

	results := sink.Send(records)

	if results[0].Err != nil {
		t.Errorf("first record should succeed, got: %v", results[0].Err)
	}
	if results[1].Err == nil {
		t.Error("second record should fail")
	}
	if results[1].Err != nil && !strings.Contains(results[1].Err.Error(), "mapper_parsing_exception") {
		t.Errorf("error should mention error type, got: %v", results[1].Err)
	}
}

func TestElasticsearch_Send_BasicAuth(t *testing.T) {
	var receivedUser, receivedPass string

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedUser, receivedPass, _ = r.BasicAuth()
		w.WriteHeader(200)
		w.Write([]byte(`{"errors":false,"items":[{"index":{"status":201}}]}`))
	}))
	defer server.Close()

	sink, err := NewElasticsearch(ElasticConfig{
		Endpoint: server.URL,
		Index:    "test",
		Username: "elastic",
		Password: "changeme",
	}, testLogger())
	if err != nil {
		t.Fatal(err)
	}
	defer sink.Close()

	sink.Send([]Record{{Data: []byte(`{}`)}})

	if receivedUser != "elastic" || receivedPass != "changeme" {
		t.Errorf("basic auth = %s:%s", receivedUser, receivedPass)
	}
}

// ── Webhook Tests ───────────────────────────────────────

func TestNewWebhook_Validation(t *testing.T) {
	logger := testLogger()

	_, err := NewWebhook(WebhookConfig{}, logger)
	if err == nil {
		t.Fatal("expected error for empty URL")
	}
	if !strings.Contains(err.Error(), "webhook URL required") {
		t.Errorf("error = %q", err.Error())
	}

	sink, err := NewWebhook(WebhookConfig{URL: "https://example.com/hook"}, logger)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	sink.Close()
}

func TestWebhook_Send(t *testing.T) {
	var mu sync.Mutex
	var receivedBodies []string
	var receivedHeaders http.Header

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		receivedHeaders = r.Header.Clone()
		body, _ := io.ReadAll(r.Body)
		receivedBodies = append(receivedBodies, string(body))
		w.WriteHeader(200)
	}))
	defer server.Close()

	sink, err := NewWebhook(WebhookConfig{
		URL: server.URL,
		Headers: map[string]string{
			"X-API-Key":    "secret123",
			"X-Custom":     "value",
		},
	}, testLogger())
	if err != nil {
		t.Fatal(err)
	}
	defer sink.Close()

	records := []Record{
		{Data: []byte(`{"event":"one"}`)},
		{Data: []byte(`{"event":"two"}`)},
	}

	results := sink.Send(records)

	if len(results) != 2 {
		t.Fatalf("expected 2 results, got %d", len(results))
	}
	for i, r := range results {
		if r.Err != nil {
			t.Errorf("result[%d] error = %v", i, r.Err)
		}
	}

	mu.Lock()
	defer mu.Unlock()

	// Webhook sends individual POSTs, not batched
	if len(receivedBodies) != 2 {
		t.Fatalf("expected 2 POSTs (one per record), got %d", len(receivedBodies))
	}

	// Check custom headers
	if receivedHeaders.Get("X-API-Key") != "secret123" {
		t.Errorf("X-API-Key = %q", receivedHeaders.Get("X-API-Key"))
	}
	if receivedHeaders.Get("User-Agent") != "cicdecoy-siem-forwarder/1.0" {
		t.Errorf("User-Agent = %q", receivedHeaders.Get("User-Agent"))
	}
}

func TestWebhook_Send_ServerError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(500)
	}))
	defer server.Close()

	sink, err := NewWebhook(WebhookConfig{URL: server.URL}, testLogger())
	if err != nil {
		t.Fatal(err)
	}
	defer sink.Close()

	results := sink.Send([]Record{{Data: []byte(`{}`)}})
	if results[0].Err == nil {
		t.Error("expected error for 500 response")
	}
	if !strings.Contains(results[0].Err.Error(), "500") {
		t.Errorf("error = %v", results[0].Err)
	}
}

// ── Syslog Tests ────────────────────────────────────────

func TestNewSyslog_Defaults(t *testing.T) {
	// Start a TCP listener for the syslog sink to connect to
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to create listener: %v", err)
	}
	defer listener.Close()

	// Accept connections in background
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			conn.Close()
		}
	}()

	sink, err := NewSyslog(SyslogConfig{
		Endpoint: listener.Addr().String(),
	}, testLogger())
	if err != nil {
		t.Fatalf("NewSyslog error: %v", err)
	}
	defer sink.Close()

	// Verify defaults were applied
	if sink.cfg.Protocol != "tcp" {
		t.Errorf("protocol = %q, want tcp", sink.cfg.Protocol)
	}
	if sink.cfg.Facility != "local0" {
		t.Errorf("facility = %q, want local0", sink.cfg.Facility)
	}
}

func TestSyslog_Send(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	var mu sync.Mutex
	var received []string

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 8192)
				for {
					n, err := c.Read(buf)
					if err != nil {
						return
					}
					mu.Lock()
					received = append(received, string(buf[:n]))
					mu.Unlock()
				}
			}(conn)
		}
	}()

	sink, err := NewSyslog(SyslogConfig{
		Endpoint: listener.Addr().String(),
		Protocol: "tcp",
		Facility: "local1",
	}, testLogger())
	if err != nil {
		t.Fatal(err)
	}
	defer sink.Close()

	records := []Record{
		{Data: []byte(`{"event_type":"command.exec","source_ip":"10.0.0.1"}`)},
	}

	results := sink.Send(records)

	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if results[0].Err != nil {
		t.Errorf("result error = %v", results[0].Err)
	}

	// Give the TCP receiver time to read
	time.Sleep(100 * time.Millisecond)

	mu.Lock()
	defer mu.Unlock()

	if len(received) == 0 {
		t.Fatal("no data received by syslog listener")
	}

	msg := received[0]
	// Should be RFC 5424 format with facility*8+6 priority
	// local1 = 17, so priority = 17*8+6 = 142
	if !strings.HasPrefix(msg, "<142>1 ") {
		t.Errorf("syslog message should start with <142>1, got: %s", msg[:min(len(msg), 50)])
	}
	if !strings.Contains(msg, "cicdecoy") {
		t.Errorf("syslog message should contain 'cicdecoy': %s", msg)
	}
	if !strings.Contains(msg, "command.exec") {
		t.Errorf("syslog message should contain event data: %s", msg)
	}
}

func TestFacilityCode(t *testing.T) {
	tests := []struct {
		facility string
		want     int
	}{
		{"local0", 16},
		{"local1", 17},
		{"local7", 23},
		{"LOCAL0", 16}, // case insensitive
		{"invalid", 16}, // default
		{"", 16},
	}

	for _, tc := range tests {
		t.Run(tc.facility, func(t *testing.T) {
			got := facilityCode(tc.facility)
			if got != tc.want {
				t.Errorf("facilityCode(%q) = %d, want %d", tc.facility, got, tc.want)
			}
		})
	}
}

func TestTruncateStr(t *testing.T) {
	tests := []struct {
		name string
		s    string
		max  int
		want string
	}{
		{"short", "hello", 10, "hello"},
		{"exact", "hello", 5, "hello"},
		{"long", "hello world", 5, "hello..."},
		{"empty", "", 5, ""},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := truncateStr(tc.s, tc.max)
			if got != tc.want {
				t.Errorf("truncateStr(%q, %d) = %q, want %q", tc.s, tc.max, got, tc.want)
			}
		})
	}
}

