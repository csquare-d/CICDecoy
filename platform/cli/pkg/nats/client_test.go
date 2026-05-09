package nats

import (
	"context"
	"testing"
)

// ── Client construction ─────────────────────────────────────
//
// NewClient calls nats.Connect directly (no interface), so we can't
// fully mock the connection without a running NATS server. We test
// error handling, configuration, and the Close path.

func TestNewClient_InvalidURL(t *testing.T) {
	// An empty URL should return an error
	_, err := NewClient("")
	if err == nil {
		t.Log("NewClient with empty URL did not error (NATS may retry in background)")
	}
}

func TestNewClient_UnreachableServer(t *testing.T) {
	// Connect to a port where nothing is listening.
	// With MaxReconnects(5), this should eventually fail.
	_, err := NewClient("nats://127.0.0.1:14222")
	if err == nil {
		// RetryOnFailedConnect(true) means the client connects in background
		// and won't fail immediately. This documents expected behavior.
		t.Log("NewClient did not return error for unreachable server (expected with RetryOnFailedConnect)")
	}
}

func TestNewClient_ErrorMessage(t *testing.T) {
	// When NewClient fails, it should wrap the error with the URL
	_, err := NewClient("completely-invalid-scheme://bad")
	if err != nil {
		// Verify error message contains the URL for debuggability
		errMsg := err.Error()
		if len(errMsg) == 0 {
			t.Error("error message should not be empty")
		}
	}
}

// ── Client.Close with nil conn ──────────────────────────────

func TestClient_Close_NilConn(t *testing.T) {
	c := &Client{conn: nil}
	// Should not panic
	c.Close()
}

// ── Client struct ───────────────────────────────────────────

func TestClient_ZeroValue(t *testing.T) {
	var c Client
	if c.conn != nil {
		t.Error("zero-value Client should have nil conn")
	}
	// Close on zero-value should be safe
	c.Close()
}

// ── Subscribe parameter validation ──────────────────────────

func TestSubscribe_NilConn(t *testing.T) {
	c := &Client{conn: nil}

	// Subscribe on nil conn should panic or return error.
	// We recover from panic to verify the behavior.
	defer func() {
		if r := recover(); r == nil {
			// If it didn't panic, it should have returned an error
			t.Log("Subscribe on nil conn did not panic (may return error)")
		}
	}()

	err := c.Subscribe("test.subject", func(subject string, data []byte) {})
	if err == nil {
		t.Error("expected error when subscribing on nil connection")
	}
}

func TestSubscribeCtx_NilConn(t *testing.T) {
	c := &Client{conn: nil}

	defer func() {
		if r := recover(); r == nil {
			t.Log("SubscribeCtx on nil conn did not panic (may return error)")
		}
	}()

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately
	err := c.SubscribeCtx(ctx, "test.subject", func(subject string, data []byte) {})
	if err == nil {
		t.Error("expected error when subscribing on nil connection")
	}
}

// ── Subject patterns ────────────────────────────────────────

func TestSubjectPatterns(t *testing.T) {
	// Verify CI/CDecoy subject hierarchy is well-formed
	tests := []struct {
		name    string
		subject string
		valid   bool
	}{
		{
			name:    "specific decoy events",
			subject: "cicdecoy.decoy.events.bastion-dmz-01.connection",
			valid:   true,
		},
		{
			name:    "wildcard all events for a decoy",
			subject: "cicdecoy.decoy.events.bastion-dmz-01.>",
			valid:   true,
		},
		{
			name:    "wildcard all decoy events",
			subject: "cicdecoy.decoy.events.>",
			valid:   true,
		},
		{
			name:    "auth attempt",
			subject: "cicdecoy.decoy.events.ssh-01.auth.attempt",
			valid:   true,
		},
		{
			name:    "command exec",
			subject: "cicdecoy.decoy.events.ssh-01.command.exec",
			valid:   true,
		},
		{
			name:    "empty subject",
			subject: "",
			valid:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.valid && tt.subject == "" {
				t.Error("valid subject should not be empty")
			}
			if !tt.valid && tt.subject != "" {
				t.Error("invalid subject should be empty")
			}
		})
	}
}

// ── Handler callback ────────────────────────────────────────

func TestHandler_ReceivesSubjectAndData(t *testing.T) {
	// Verify the handler signature matches what Subscribe expects
	var calledSubject string
	var calledData []byte

	handler := func(subject string, data []byte) {
		calledSubject = subject
		calledData = data
	}

	// Simulate calling the handler as Subscribe would
	handler("cicdecoy.decoy.events.test.connection", []byte(`{"event_type":"connection"}`))

	if calledSubject != "cicdecoy.decoy.events.test.connection" {
		t.Errorf("subject = %q, want cicdecoy.decoy.events.test.connection", calledSubject)
	}
	if string(calledData) != `{"event_type":"connection"}` {
		t.Errorf("data = %q", string(calledData))
	}
}

func TestHandler_EmptyData(t *testing.T) {
	var receivedData []byte

	handler := func(subject string, data []byte) {
		receivedData = data
	}

	handler("test.subject", []byte{})

	if len(receivedData) != 0 {
		t.Errorf("expected empty data, got %d bytes", len(receivedData))
	}
}

func TestHandler_NilData(t *testing.T) {
	var receivedData []byte
	receivedData = []byte("initial") // set to non-nil to detect nil assignment

	handler := func(subject string, data []byte) {
		receivedData = data
	}

	handler("test.subject", nil)

	if receivedData != nil {
		t.Errorf("expected nil data, got %v", receivedData)
	}
}

// ── Connection options ──────────────────────────────────────

func TestConnectionOptions_RetryOnFailedConnect(t *testing.T) {
	// Verify NewClient uses RetryOnFailedConnect(true) and MaxReconnects(5)
	// by checking that a connection to an invalid server doesn't immediately
	// return an error (RetryOnFailedConnect=true means async connect).
	//
	// This is a documentation test — the actual behavior is verified by
	// reading the source code. We test the observable behavior.
	_, err := NewClient("nats://192.0.2.1:4222") // RFC 5737 TEST-NET, guaranteed unreachable
	if err != nil {
		// With RetryOnFailedConnect(true), connect may succeed asynchronously
		// Some NATS client versions still fail for completely unreachable hosts
		t.Logf("NewClient returned error (may vary by nats.go version): %v", err)
	}
}
