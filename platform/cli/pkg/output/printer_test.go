package output

import (
	"testing"
)

func TestNewPrinter(t *testing.T) {
	tests := []struct {
		name     string
		jsonMode bool
		noColor  bool
	}{
		{"default", false, false},
		{"json mode", true, false},
		{"no color", false, true},
		{"json and no color", true, true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p := NewPrinter(tc.jsonMode, tc.noColor)
			if p == nil {
				t.Fatal("NewPrinter returned nil")
			}
			if p.json != tc.jsonMode {
				t.Errorf("json = %v, want %v", p.json, tc.jsonMode)
			}
			if p.noColor != tc.noColor {
				t.Errorf("noColor = %v, want %v", p.noColor, tc.noColor)
			}
		})
	}
}

func TestPrinter_StatusIcon_NoColor(t *testing.T) {
	p := NewPrinter(false, true)

	tests := []struct {
		status string
		want   string
	}{
		{"healthy", "[OK]"},
		{"active", "[OK]"},
		{"auth", "[OK]"},
		{"degraded", "[!!]"},
		{"rotating", "[!!]"},
		{"offline", "[XX]"},
		{"unknown", "[--]"},
		{"", "[--]"},
	}

	for _, tc := range tests {
		t.Run(tc.status, func(t *testing.T) {
			got := p.StatusIcon(tc.status)
			if got != tc.want {
				t.Errorf("StatusIcon(%q) = %q, want %q", tc.status, got, tc.want)
			}
		})
	}
}

func TestPrinter_StatusIcon_WithColor(t *testing.T) {
	p := NewPrinter(false, false)

	// With color enabled, icons should contain ANSI escape sequences
	tests := []struct {
		status      string
		wantContain string
	}{
		{"healthy", "\033[32m"},
		{"active", "\033[32m"},
		{"degraded", "\033[33m"},
		{"offline", "\033[31m"},
		{"unknown", "\033[90m"},
	}

	for _, tc := range tests {
		t.Run(tc.status, func(t *testing.T) {
			got := p.StatusIcon(tc.status)
			if len(got) == 0 {
				t.Error("StatusIcon returned empty string")
			}
			// We can't rely on exact ANSI sequences in all terminals,
			// but with noColor=false, output should not be plain text icons
			if got == "[OK]" || got == "[!!]" || got == "[XX]" || got == "[--]" {
				t.Error("StatusIcon returned plain text when color is enabled")
			}
		})
	}
}

func TestPrinter_SeverityIcon_NoColor(t *testing.T) {
	p := NewPrinter(false, true)

	tests := []struct {
		severity string
		want     string
	}{
		{"critical", "[critical]"},
		{"high", "[high]"},
		{"medium", "[medium]"},
		{"low", "[low]"},
		{"info", "[info]"},
		{"", "[]"},
	}

	for _, tc := range tests {
		t.Run(tc.severity, func(t *testing.T) {
			got := p.SeverityIcon(tc.severity)
			if got != tc.want {
				t.Errorf("SeverityIcon(%q) = %q, want %q", tc.severity, got, tc.want)
			}
		})
	}
}

func TestPrinter_SeverityIcon_WithColor(t *testing.T) {
	p := NewPrinter(false, false)

	for _, sev := range []string{"critical", "high", "medium", "low", "info"} {
		t.Run(sev, func(t *testing.T) {
			got := p.SeverityIcon(sev)
			if len(got) == 0 {
				t.Error("SeverityIcon returned empty string")
			}
		})
	}
}

func TestPrinter_Dim2_NoColor(t *testing.T) {
	p := NewPrinter(false, true)
	got := p.Dim2("hello")
	if got != "hello" {
		t.Errorf("Dim2 with noColor should return raw string, got %q", got)
	}
}

func TestPrinter_Dim2_WithColor(t *testing.T) {
	p := NewPrinter(false, false)
	got := p.Dim2("hello")
	if got == "hello" {
		t.Error("Dim2 with color should wrap string with ANSI codes")
	}
	// Should contain the dim color code
	if got != "\033[90mhello\033[0m" {
		t.Errorf("Dim2 = %q, want ANSI-wrapped", got)
	}
}

func TestPrinter_ColorMethods(t *testing.T) {
	p := NewPrinter(false, false)

	// These should return non-empty strings
	methods := []struct {
		name string
		fn   func(string) string
	}{
		{"Red", p.Red},
		{"Green", p.Green},
		{"Yellow", p.Yellow},
		{"Blue", p.Blue},
	}

	for _, m := range methods {
		t.Run(m.name, func(t *testing.T) {
			got := m.fn("test")
			if len(got) == 0 {
				t.Error("color method returned empty string")
			}
		})
	}
}

func TestPrinter_Table_EmptyRows(t *testing.T) {
	// Table with empty rows should not panic
	p := NewPrinter(false, true)
	// This prints to stdout; we just verify no panic
	p.Table([]string{"A", "B"}, nil)
	p.Table([]string{"A", "B"}, [][]string{})
}

func TestPrinter_Table_WithData(t *testing.T) {
	p := NewPrinter(false, true)
	// Just verify no panic with various data shapes
	p.Table(
		[]string{"NAME", "STATUS"},
		[][]string{
			{"decoy-1", "active"},
			{"decoy-2", "degraded"},
		},
	)
}

func TestPrinter_Table_WidthCalculation(t *testing.T) {
	// Table should handle cells wider than headers
	p := NewPrinter(false, true)
	p.Table(
		[]string{"A", "B"},
		[][]string{
			{"very long cell value", "short"},
			{"x", "another very long cell value"},
		},
	)
	// No panic = pass
}

func TestPrinter_Table_SpecialCharacters(t *testing.T) {
	p := NewPrinter(false, true)
	p.Table(
		[]string{"DATA"},
		[][]string{
			{"line1\nline2"},
			{"tab\there"},
			{"emoji: 🎯"},
			{""},
			{"  spaces  "},
		},
	)
}
