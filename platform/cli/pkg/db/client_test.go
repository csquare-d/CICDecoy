package db

import (
	"testing"
	"time"
)

// ── parseDuration tests ─────────────────────────────────

func TestParseDuration(t *testing.T) {
	tests := []struct {
		name string
		input string
		want  time.Duration
	}{
		{
			name:  "days suffix",
			input: "7d",
			want:  7 * 24 * time.Hour,
		},
		{
			name:  "single day",
			input: "1d",
			want:  24 * time.Hour,
		},
		{
			name:  "30 days",
			input: "30d",
			want:  30 * 24 * time.Hour,
		},
		{
			name:  "hours",
			input: "2h",
			want:  2 * time.Hour,
		},
		{
			name:  "minutes",
			input: "30m",
			want:  30 * time.Minute,
		},
		{
			name:  "seconds",
			input: "60s",
			want:  60 * time.Second,
		},
		{
			name:  "complex duration",
			input: "1h30m",
			want:  90 * time.Minute,
		},
		{
			name:  "empty string defaults to 24h",
			input: "",
			want:  24 * time.Hour,
		},
		{
			name:  "invalid string defaults to 24h",
			input: "notaduration",
			want:  24 * time.Hour,
		},
		{
			name:  "whitespace around days",
			input: " 7d ",
			want:  7 * 24 * time.Hour,
		},
		{
			name:  "zero days defaults to 24h",
			input: "0d",
			want:  24 * time.Hour,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := parseDuration(tc.input)
			if got != tc.want {
				t.Errorf("parseDuration(%q) = %v, want %v", tc.input, got, tc.want)
			}
		})
	}
}

// ── Data type tests ─────────────────────────────────────

func TestSessionQuery_Defaults(t *testing.T) {
	// Verify zero values of SessionQuery
	q := SessionQuery{}
	if q.LiveOnly != false {
		t.Error("LiveOnly default should be false")
	}
	if q.Limit != 0 {
		t.Error("Limit default should be 0")
	}
	if q.Severity != "" {
		t.Error("Severity default should be empty")
	}
	if q.Decoy != "" {
		t.Error("Decoy default should be empty")
	}
	if q.Since != "" {
		t.Error("Since default should be empty")
	}
}

func TestSessionRow_Fields(t *testing.T) {
	row := SessionRow{
		SessionID: "sess-abc123",
		DecoyName: "ssh-dmz-01",
		SourceIP:  "198.51.100.42",
		Country:   "US",
		Username:  "root",
		StartTime: "2025-03-26T14:03:22Z",
		Commands:  5,
		Severity:  "high",
		Phase:     "discovery",
		Tools:     []string{"nmap", "curl"},
	}

	if row.SessionID != "sess-abc123" {
		t.Errorf("SessionID = %q", row.SessionID)
	}
	if len(row.Tools) != 2 {
		t.Errorf("Tools count = %d", len(row.Tools))
	}
}

func TestSessionEvent_Fields(t *testing.T) {
	ev := SessionEvent{
		Timestamp:      "2025-03-26T14:03:22.847Z",
		EventType:      "command.exec",
		SourceIP:       "10.0.0.1",
		Username:       "admin",
		Command:        "ls -la",
		Response:       "total 0\n...",
		Severity:       "medium",
		MITRETechnique: "T1083",
		MITREName:      "File and Directory Discovery",
	}

	if ev.EventType != "command.exec" {
		t.Errorf("EventType = %q", ev.EventType)
	}
	if ev.MITRETechnique != "T1083" {
		t.Errorf("MITRETechnique = %q", ev.MITRETechnique)
	}
}

func TestIOCRow_Fields(t *testing.T) {
	ioc := IOCRow{
		Type:       "ip",
		Value:      "198.51.100.42",
		Severity:   "high",
		Confidence: 85,
		Sightings:  12,
		FirstSeen:  "2025-03-20",
		LastSeen:   "2025-03-26",
		Techniques: []string{"T1059", "T1083"},
	}

	if ioc.Confidence != 85 {
		t.Errorf("Confidence = %d", ioc.Confidence)
	}
	if len(ioc.Techniques) != 2 {
		t.Errorf("Techniques count = %d", len(ioc.Techniques))
	}
}

func TestActorRow_Fields(t *testing.T) {
	actor := ActorRow{
		SourceIP:   "10.0.0.1",
		Country:    "CN",
		Sessions:   5,
		Commands:   42,
		Severity:   "critical",
		Techniques: []string{"T1059.004"},
		FirstSeen:  "2025-03-01",
		LastSeen:   "2025-03-26",
	}

	if actor.Sessions != 5 {
		t.Errorf("Sessions = %d", actor.Sessions)
	}
	if actor.Country != "CN" {
		t.Errorf("Country = %q", actor.Country)
	}
}

func TestMITRETechRow_Fields(t *testing.T) {
	row := MITRETechRow{
		TechniqueID: "T1059.004",
		Name:        "Unix Shell",
		Count:       15,
	}

	if row.TechniqueID != "T1059.004" {
		t.Errorf("TechniqueID = %q", row.TechniqueID)
	}
	if row.Count != 15 {
		t.Errorf("Count = %d", row.Count)
	}
}

func TestHoneytokenRow_Fields(t *testing.T) {
	ht := HoneytokenRow{
		Name:        "fake-aws-key",
		Type:        "aws_access_key",
		Decoy:       "ssh-dmz-01",
		Triggered:   3,
		LastTrigger: "2025-03-26 14:00",
		SourceIP:    "10.0.0.5",
	}

	if ht.Name != "fake-aws-key" {
		t.Errorf("Name = %q", ht.Name)
	}
	if ht.Triggered != 3 {
		t.Errorf("Triggered = %d", ht.Triggered)
	}
}
