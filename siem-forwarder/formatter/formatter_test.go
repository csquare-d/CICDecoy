package formatter

import (
	"encoding/json"
	"strings"
	"testing"
)

// ── JSON Formatter ──────────────────────────────────────

func TestJSONFormatter_Name(t *testing.T) {
	f := NewJSON()
	if got := f.Name(); got != "json" {
		t.Errorf("Name() = %q, want %q", got, "json")
	}
}

func TestJSONFormatter_Format(t *testing.T) {
	f := NewJSON()

	tests := []struct {
		name    string
		subject string
		event   map[string]interface{}
		check   func(t *testing.T, out map[string]interface{})
	}{
		{
			name:    "injects source and format version",
			subject: "cicdecoy.events.ssh-01.command.exec",
			event: map[string]interface{}{
				"event_type": "command.exec",
				"timestamp":  "2025-03-26T14:03:22Z",
				"source_ip":  "198.51.100.42",
			},
			check: func(t *testing.T, out map[string]interface{}) {
				if out["_source"] != "cicdecoy" {
					t.Errorf("_source = %v, want cicdecoy", out["_source"])
				}
				if out["_format_version"] != "1.0" {
					t.Errorf("_format_version = %v, want 1.0", out["_format_version"])
				}
				if out["timestamp"] != "2025-03-26T14:03:22Z" {
					t.Errorf("timestamp = %v, want original", out["timestamp"])
				}
			},
		},
		{
			name:    "injects timestamp when missing",
			subject: "cicdecoy.events.test",
			event: map[string]interface{}{
				"event_type": "connection.new",
			},
			check: func(t *testing.T, out map[string]interface{}) {
				ts, ok := out["timestamp"].(string)
				if !ok || ts == "" {
					t.Error("expected non-empty timestamp to be injected")
				}
			},
		},
		{
			name:    "preserves all original fields",
			subject: "cicdecoy.events.test",
			event: map[string]interface{}{
				"event_type": "auth.success",
				"timestamp":  "2025-01-01T00:00:00Z",
				"source_ip":  "10.0.0.1",
				"username":   "admin",
				"custom":     "value",
			},
			check: func(t *testing.T, out map[string]interface{}) {
				if out["event_type"] != "auth.success" {
					t.Errorf("event_type = %v", out["event_type"])
				}
				if out["source_ip"] != "10.0.0.1" {
					t.Errorf("source_ip = %v", out["source_ip"])
				}
				if out["custom"] != "value" {
					t.Errorf("custom = %v", out["custom"])
				}
			},
		},
		{
			name:    "empty event",
			subject: "cicdecoy.events.test",
			event:   map[string]interface{}{},
			check: func(t *testing.T, out map[string]interface{}) {
				if out["_source"] != "cicdecoy" {
					t.Error("should still inject _source")
				}
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			data, err := f.Format(tc.subject, tc.event)
			if err != nil {
				t.Fatalf("Format() error = %v", err)
			}
			var out map[string]interface{}
			if err := json.Unmarshal(data, &out); err != nil {
				t.Fatalf("output is not valid JSON: %v", err)
			}
			tc.check(t, out)
		})
	}
}

// ── CEF Formatter ───────────────────────────────────────

func TestCEFFormatter_Name(t *testing.T) {
	f := NewCEF()
	if got := f.Name(); got != "cef" {
		t.Errorf("Name() = %q, want %q", got, "cef")
	}
}

func TestCEFFormatter_Format(t *testing.T) {
	f := NewCEF()

	tests := []struct {
		name           string
		subject        string
		event          map[string]interface{}
		wantPrefix     string
		wantContains   []string
		wantNotContain []string
	}{
		{
			name:    "command exec event",
			subject: "cicdecoy.events.bastion-01.command.exec",
			event: map[string]interface{}{
				"event_type": "command.exec",
				"source_ip":  "198.51.100.42",
				"decoy_name": "bastion-01",
				"session_id": "sess-abc123",
				"protocol":   "ssh",
				"timestamp":  "2025-03-26T14:03:22Z",
				"data": map[string]interface{}{
					"command":  "cat /etc/passwd",
					"username": "root",
				},
			},
			wantPrefix: "CEF:0|CICDecoy|SIEMForwarder|1.0|CICD-3001|Command Executed in Decoy|5|",
			wantContains: []string{
				"src=198.51.100.42",
				"dhost=bastion-01",
				"proto=ssh",
				"cs2=cat /etc/passwd",
				"cs2Label=Command",
				"suser=root",
			},
		},
		{
			name:    "auth success event",
			subject: "cicdecoy.events.ssh-01.auth.success",
			event: map[string]interface{}{
				"event_type": "auth.success",
				"source_ip":  "10.0.0.1",
				"username":   "admin",
			},
			wantPrefix: "CEF:0|CICDecoy|SIEMForwarder|1.0|CICD-2002|Authentication Success|6|",
			wantContains: []string{
				"src=10.0.0.1",
				"suser=admin",
			},
		},
		{
			name:    "falco alert sets cs4",
			subject: "cicdecoy.falco.alerts",
			event: map[string]interface{}{
				"event_type": "falco.alert",
				"rule":       "Write below /etc",
				"output":     "File below /etc opened for writing",
				"source_ip":  "10.0.0.2",
			},
			wantContains: []string{
				"cs4=Write below /etc",
				"cs4Label=FalcoRule",
				"msg=File below /etc opened for writing",
			},
		},
		{
			name:    "unknown event type gets default signature",
			subject: "cicdecoy.events.test",
			event: map[string]interface{}{
				"event_type": "custom.unknown",
			},
			wantContains: []string{
				"CICD-9999",
				"CICDecoy Event: custom.unknown",
			},
		},
		{
			name:    "special characters are escaped",
			subject: "cicdecoy.events.test",
			event: map[string]interface{}{
				"event_type": "command.exec",
				"source_ip":  "10.0.0.1",
				"data": map[string]interface{}{
					"command": "echo 'hello|world=test'",
				},
			},
			wantContains: []string{
				`hello\|world\=test`,
			},
		},
		{
			name:    "empty event still produces valid CEF",
			subject: "cicdecoy.events.test",
			event:   map[string]interface{}{},
			wantPrefix: "CEF:0|CICDecoy|SIEMForwarder|1.0|",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			data, err := f.Format(tc.subject, tc.event)
			if err != nil {
				t.Fatalf("Format() error = %v", err)
			}
			out := string(data)
			if tc.wantPrefix != "" && !strings.HasPrefix(out, tc.wantPrefix) {
				t.Errorf("output prefix mismatch\ngot:  %s\nwant: %s...", out[:min(len(out), len(tc.wantPrefix)+20)], tc.wantPrefix)
			}
			for _, want := range tc.wantContains {
				if !strings.Contains(out, want) {
					t.Errorf("output missing %q\ngot: %s", want, out)
				}
			}
			for _, notWant := range tc.wantNotContain {
				if strings.Contains(out, notWant) {
					t.Errorf("output should not contain %q\ngot: %s", notWant, out)
				}
			}
		})
	}
}

// ── LEEF Formatter ──────────────────────────────────────

func TestLEEFFormatter_Name(t *testing.T) {
	f := NewLEEF()
	if got := f.Name(); got != "leef" {
		t.Errorf("Name() = %q, want %q", got, "leef")
	}
}

func TestLEEFFormatter_Format(t *testing.T) {
	f := NewLEEF()

	tests := []struct {
		name         string
		subject      string
		event        map[string]interface{}
		wantPrefix   string
		wantContains []string
	}{
		{
			name:    "command exec event",
			subject: "cicdecoy.events.bastion.command.exec",
			event: map[string]interface{}{
				"event_type": "command.exec",
				"source_ip":  "192.168.1.1",
				"decoy_name": "bastion-dmz-01",
				"session_id": "sess-xyz",
				"protocol":   "ssh",
				"timestamp":  "2025-03-26T14:03:22Z",
				"data": map[string]interface{}{
					"command": "whoami",
				},
			},
			wantPrefix: "LEEF:2.0|CICDecoy|SIEMForwarder|1.0|CICD-3001|",
			wantContains: []string{
				"src=192.168.1.1",
				"dstName=bastion-dmz-01",
				"proto=ssh",
				"command=whoami",
				"sev=5",
			},
		},
		{
			name:    "auth attempt event",
			subject: "cicdecoy.events.test",
			event: map[string]interface{}{
				"event_type": "auth.attempt",
				"source_ip":  "10.0.0.5",
				"username":   "testuser",
			},
			wantPrefix: "LEEF:2.0|CICDecoy|SIEMForwarder|1.0|CICD-2001|",
			wantContains: []string{
				"src=10.0.0.5",
				"usrName=testuser",
				"sev=4",
			},
		},
		{
			name:    "tab-separated key-value pairs",
			subject: "cicdecoy.events.test",
			event: map[string]interface{}{
				"event_type": "connection.new",
				"source_ip":  "10.0.0.1",
				"source_port": "12345",
			},
			wantContains: []string{
				"\tsrc=10.0.0.1",
				"\tsrcPort=12345",
			},
		},
		{
			name:    "empty event produces valid LEEF",
			subject: "cicdecoy.events.test",
			event:   map[string]interface{}{},
			wantPrefix: "LEEF:2.0|CICDecoy|SIEMForwarder|1.0|",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			data, err := f.Format(tc.subject, tc.event)
			if err != nil {
				t.Fatalf("Format() error = %v", err)
			}
			out := string(data)
			if tc.wantPrefix != "" && !strings.HasPrefix(out, tc.wantPrefix) {
				t.Errorf("output prefix mismatch\ngot:  %s\nwant: %s...", out[:min(len(out), len(tc.wantPrefix)+20)], tc.wantPrefix)
			}
			for _, want := range tc.wantContains {
				if !strings.Contains(out, want) {
					t.Errorf("output missing %q\ngot: %s", want, out)
				}
			}
		})
	}
}

// ── ECS Formatter ───────────────────────────────────────

func TestECSFormatter_Name(t *testing.T) {
	f := NewECS()
	if got := f.Name(); got != "ecs" {
		t.Errorf("Name() = %q, want %q", got, "ecs")
	}
}

func TestECSFormatter_Format(t *testing.T) {
	f := NewECS()

	tests := []struct {
		name    string
		subject string
		event   map[string]interface{}
		check   func(t *testing.T, out map[string]interface{})
	}{
		{
			name:    "command exec maps to ECS fields",
			subject: "cicdecoy.events.bastion.command.exec",
			event: map[string]interface{}{
				"event_type": "command.exec",
				"event_id":   "evt-001",
				"timestamp":  "2025-03-26T14:03:22Z",
				"source_ip":  "198.51.100.42",
				"source_port": 54321,
				"decoy_name": "bastion-dmz-01",
				"decoy_tier": 2,
				"protocol":   "ssh",
				"session_id": "sess-xyz",
				"data": map[string]interface{}{
					"command": "cat /etc/passwd",
				},
			},
			check: func(t *testing.T, out map[string]interface{}) {
				if out["@timestamp"] != "2025-03-26T14:03:22Z" {
					t.Errorf("@timestamp = %v", out["@timestamp"])
				}
				if out["message"] != "command.exec" {
					t.Errorf("message = %v", out["message"])
				}
				tags, ok := out["tags"].([]interface{})
				if !ok || len(tags) != 2 {
					t.Errorf("tags = %v", out["tags"])
				}

				ev := out["event"].(map[string]interface{})
				if ev["kind"] != "alert" {
					t.Errorf("event.kind = %v", ev["kind"])
				}
				if ev["module"] != "cicdecoy" {
					t.Errorf("event.module = %v", ev["module"])
				}
				if ev["id"] != "evt-001" {
					t.Errorf("event.id = %v", ev["id"])
				}

				src := out["source"].(map[string]interface{})
				if src["ip"] != "198.51.100.42" {
					t.Errorf("source.ip = %v", src["ip"])
				}

				obs := out["observer"].(map[string]interface{})
				if obs["name"] != "bastion-dmz-01" {
					t.Errorf("observer.name = %v", obs["name"])
				}
				if obs["type"] != "honeypot" {
					t.Errorf("observer.type = %v", obs["type"])
				}

				proc := out["process"].(map[string]interface{})
				if proc["command_line"] != "cat /etc/passwd" {
					t.Errorf("process.command_line = %v", proc["command_line"])
				}

				cicdecoy := out["cicdecoy"].(map[string]interface{})
				if cicdecoy["session_id"] != "sess-xyz" {
					t.Errorf("cicdecoy.session_id = %v", cicdecoy["session_id"])
				}
			},
		},
		{
			name:    "adds user field when username present",
			subject: "cicdecoy.events.test",
			event: map[string]interface{}{
				"event_type": "auth.success",
				"username":   "admin",
				"timestamp":  "2025-01-01T00:00:00Z",
			},
			check: func(t *testing.T, out map[string]interface{}) {
				user, ok := out["user"].(map[string]interface{})
				if !ok {
					t.Fatal("user field missing")
				}
				if user["name"] != "admin" {
					t.Errorf("user.name = %v", user["name"])
				}
			},
		},
		{
			name:    "no user field when username absent",
			subject: "cicdecoy.events.test",
			event: map[string]interface{}{
				"event_type": "connection.new",
				"timestamp":  "2025-01-01T00:00:00Z",
			},
			check: func(t *testing.T, out map[string]interface{}) {
				if _, ok := out["user"]; ok {
					t.Error("user field should be absent")
				}
			},
		},
		{
			name:    "falco event adds rule and changes category",
			subject: "cicdecoy.falco.alerts",
			event: map[string]interface{}{
				"event_type": "falco.alert",
				"rule":       "Write below /etc",
				"output":     "File opened for writing",
				"priority":   "critical",
				"timestamp":  "2025-01-01T00:00:00Z",
			},
			check: func(t *testing.T, out map[string]interface{}) {
				rule, ok := out["rule"].(map[string]interface{})
				if !ok {
					t.Fatal("rule field missing for falco event")
				}
				if rule["name"] != "Write below /etc" {
					t.Errorf("rule.name = %v", rule["name"])
				}
				ev := out["event"].(map[string]interface{})
				if sev, ok := ev["severity"]; !ok || sev != float64(2) {
					t.Errorf("event.severity = %v (want 2 for critical)", sev)
				}
			},
		},
		{
			name:    "empty event still produces valid ECS JSON",
			subject: "cicdecoy.events.test",
			event:   map[string]interface{}{},
			check: func(t *testing.T, out map[string]interface{}) {
				if _, ok := out["@timestamp"]; !ok {
					t.Error("@timestamp should always be present")
				}
				if _, ok := out["event"]; !ok {
					t.Error("event field should always be present")
				}
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			data, err := f.Format(tc.subject, tc.event)
			if err != nil {
				t.Fatalf("Format() error = %v", err)
			}
			var out map[string]interface{}
			if err := json.Unmarshal(data, &out); err != nil {
				t.Fatalf("output is not valid JSON: %v\nraw: %s", err, string(data))
			}
			tc.check(t, out)
		})
	}
}

// ── Helper function tests ───────────────────────────────

func TestGetString(t *testing.T) {
	m := map[string]interface{}{
		"str":    "hello",
		"num":    42,
		"float":  3.14,
		"bool":   true,
		"nested": map[string]interface{}{"a": "b"},
	}

	tests := []struct {
		key  string
		want string
	}{
		{"str", "hello"},
		{"num", "42"},
		{"float", "3.14"},
		{"bool", "true"},
		{"missing", ""},
	}

	for _, tc := range tests {
		t.Run(tc.key, func(t *testing.T) {
			got := getString(m, tc.key)
			if got != tc.want {
				t.Errorf("getString(%q) = %q, want %q", tc.key, got, tc.want)
			}
		})
	}
}

func TestGetNumber(t *testing.T) {
	m := map[string]interface{}{
		"port": 54321,
		"tier": 2,
	}

	if got := getNumber(m, "port"); got != 54321 {
		t.Errorf("getNumber(port) = %v", got)
	}
	if got := getNumber(m, "missing"); got != nil {
		t.Errorf("getNumber(missing) = %v, want nil", got)
	}
}

func TestCefEscape(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{"pipe", "hello|world", `hello\|world`},
		{"equals", "key=value", `key\=value`},
		{"backslash", `path\to\file`, `path\\to\\file`},
		{"newline", "line1\nline2", `line1\nline2`},
		{"carriage return", "line1\rline2", `line1\rline2`},
		{"combined", "a|b=c\\d\ne", `a\|b\=c\\d\ne`},
		{"empty string", "", ""},
		{"no special chars", "hello world", "hello world"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := cefEscape(tc.input)
			if got != tc.want {
				t.Errorf("cefEscape(%q) = %q, want %q", tc.input, got, tc.want)
			}
		})
	}
}

func TestEventTypeToCEFSignature(t *testing.T) {
	tests := []struct {
		eventType string
		want      string
	}{
		{"connection.new", "CICD-1001"},
		{"auth.attempt", "CICD-2001"},
		{"auth.success", "CICD-2002"},
		{"command.exec", "CICD-3001"},
		{"file.upload", "CICD-4001"},
		{"session.start", "CICD-5001"},
		{"honeytoken.trigger", "CICD-6001"},
		{"falco.alert", "CICD-7001"},
		{"unknown.type", "CICD-9999"},
		{"", "CICD-9999"},
	}

	for _, tc := range tests {
		t.Run(tc.eventType, func(t *testing.T) {
			got := eventTypeToCEFSignature(tc.eventType)
			if got != tc.want {
				t.Errorf("eventTypeToCEFSignature(%q) = %q, want %q", tc.eventType, got, tc.want)
			}
		})
	}
}

func TestMapCEFSeverity(t *testing.T) {
	tests := []struct {
		name      string
		eventType string
		subject   string
		want      int
	}{
		{"connection.new", "connection.new", "cicdecoy.events.test", 3},
		{"auth.success", "auth.success", "cicdecoy.events.test", 6},
		{"file.upload", "file.upload", "cicdecoy.events.test", 7},
		{"command.exec", "command.exec", "cicdecoy.events.test", 5},
		{"falco subject overrides", "command.exec", "cicdecoy.falco.alerts", 8},
		{"honeytoken subject overrides", "command.exec", "cicdecoy.honeytoken.events", 9},
		{"unknown defaults to 3", "totally.unknown", "cicdecoy.events.test", 3},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := mapCEFSeverity(tc.eventType, tc.subject)
			if got != tc.want {
				t.Errorf("mapCEFSeverity(%q, %q) = %d, want %d", tc.eventType, tc.subject, got, tc.want)
			}
		})
	}
}

func TestEcsEventType(t *testing.T) {
	tests := []struct {
		eventType string
		want      string
	}{
		{"connection.new", "connection"},
		{"connection.close", "connection"},
		{"auth.success", "access"},
		{"auth.failure", "access"},
		{"command.exec", "info"},
		{"file.upload", "creation"},
		{"session.start", "start"},
		{"unknown", "info"},
		{"", "info"},
	}

	for _, tc := range tests {
		t.Run(tc.eventType, func(t *testing.T) {
			got := ecsEventType(tc.eventType)
			if got != tc.want {
				t.Errorf("ecsEventType(%q) = %q, want %q", tc.eventType, got, tc.want)
			}
		})
	}
}

func TestFalcoPriorityToECS(t *testing.T) {
	tests := []struct {
		priority string
		want     int
	}{
		{"emergency", 1},
		{"alert", 1},
		{"critical", 2},
		{"error", 3},
		{"warning", 4},
		{"notice", 5},
		{"informational", 6},
		{"info", 6},
		{"debug", 7},
		{"unknown", 5},
		{"WARNING", 4}, // case insensitive
	}

	for _, tc := range tests {
		t.Run(tc.priority, func(t *testing.T) {
			got := falcoPriorityToECS(tc.priority)
			if got != tc.want {
				t.Errorf("falcoPriorityToECS(%q) = %d, want %d", tc.priority, got, tc.want)
			}
		})
	}
}

func TestCefEventName(t *testing.T) {
	tests := []struct {
		eventType string
		want      string
	}{
		{"connection.new", "New Connection to Decoy"},
		{"auth.success", "Authentication Success"},
		{"command.exec", "Command Executed in Decoy"},
		{"session.end", "Session Ended"},
		{"unknown.event", "CICDecoy Event: unknown.event"},
	}

	for _, tc := range tests {
		t.Run(tc.eventType, func(t *testing.T) {
			got := cefEventName(tc.eventType)
			if got != tc.want {
				t.Errorf("cefEventName(%q) = %q, want %q", tc.eventType, got, tc.want)
			}
		})
	}
}

// ── Formatter interface compliance ──────────────────────

func TestAllFormattersImplementInterface(t *testing.T) {
	formatters := []Formatter{
		NewJSON(),
		NewCEF(),
		NewLEEF(),
		NewECS(),
	}

	event := map[string]interface{}{
		"event_type": "command.exec",
		"timestamp":  "2025-03-26T14:03:22Z",
		"source_ip":  "10.0.0.1",
	}

	for _, f := range formatters {
		t.Run(f.Name(), func(t *testing.T) {
			out, err := f.Format("cicdecoy.events.test", event)
			if err != nil {
				t.Fatalf("Format() error = %v", err)
			}
			if len(out) == 0 {
				t.Error("Format() returned empty output")
			}
		})
	}
}

