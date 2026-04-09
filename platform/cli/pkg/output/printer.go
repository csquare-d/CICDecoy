package output

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/fatih/color"
)

type Printer struct {
	json    bool
	noColor bool
}

func NewPrinter(jsonMode, noColor bool) *Printer {
	if noColor {
		color.NoColor = true
	}
	return &Printer{json: jsonMode, noColor: noColor}
}

func (p *Printer) Ln(format ...interface{}) {
	if len(format) == 0 {
		fmt.Println()
		return
	}
	f := format[0].(string)
	if len(format) > 1 {
		fmt.Printf(f+"\n", format[1:]...)
	} else {
		fmt.Println(f)
	}
}

func (p *Printer) Header(format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	c := color.New(color.FgMagenta, color.Bold)
	c.Printf("  ◈ %s\n", msg)
	fmt.Printf("  %s\n", strings.Repeat("─", len(msg)+4))
}

func (p *Printer) Info(format string, args ...interface{}) {
	fmt.Printf("  "+format+"\n", args...)
}

func (p *Printer) Success(format string, args ...interface{}) {
	c := color.New(color.FgGreen)
	c.Printf("  ✓ "+format+"\n", args...)
}

func (p *Printer) Warn(format string, args ...interface{}) {
	c := color.New(color.FgYellow)
	c.Printf("  ⚠ "+format+"\n", args...)
}

func (p *Printer) Error(format string, args ...interface{}) {
	c := color.New(color.FgRed)
	c.Fprintf(os.Stderr, "  ✗ "+format+"\n", args...)
}

func (p *Printer) Dim(format string, args ...interface{}) {
	c := color.New(color.FgHiBlack)
	c.Printf("  "+format+"\n", args...)
}

func (p *Printer) Dim2(s string) string {
	if p.noColor {
		return s
	}
	return fmt.Sprintf("\033[90m%s\033[0m", s)
}

func (p *Printer) Red(s string) string {
	return color.RedString(s)
}

func (p *Printer) Green(s string) string {
	return color.GreenString(s)
}

func (p *Printer) Yellow(s string) string {
	return color.YellowString(s)
}

func (p *Printer) Blue(s string) string {
	return color.BlueString(s)
}

func (p *Printer) StatusIcon(status string) string {
	if p.noColor {
		switch status {
		case "healthy", "active", "auth":
			return "[OK]"
		case "degraded", "rotating":
			return "[!!]"
		case "offline":
			return "[XX]"
		default:
			return "[--]"
		}
	}
	switch status {
	case "healthy", "active":
		return "\033[32m●\033[0m"
	case "auth":
		return "\033[33m◉\033[0m"
	case "degraded", "rotating":
		return "\033[33m●\033[0m"
	case "offline":
		return "\033[31m●\033[0m"
	default:
		return "\033[90m●\033[0m"
	}
}

func (p *Printer) SeverityIcon(severity string) string {
	if p.noColor {
		return fmt.Sprintf("[%s]", severity)
	}
	switch severity {
	case "critical":
		return "\033[31m▲\033[0m"
	case "high":
		return "\033[33m▲\033[0m"
	case "medium":
		return "\033[33m◆\033[0m"
	case "low":
		return "\033[32m◆\033[0m"
	default:
		return "\033[90m·\033[0m"
	}
}

func (p *Printer) JSON(v interface{}) error {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

func (p *Printer) Table(headers []string, rows [][]string) {
	if len(rows) == 0 {
		p.Dim("  (no results)")
		fmt.Println()
		return
	}

	// Calculate column widths
	widths := make([]int, len(headers))
	for i, h := range headers {
		widths[i] = len(h)
	}
	for _, row := range rows {
		for i, cell := range row {
			if i < len(widths) && len(cell) > widths[i] {
				widths[i] = len(cell)
			}
		}
	}

	// Print header
	var hdr strings.Builder
	hdr.WriteString("  ")
	for i, h := range headers {
		hdr.WriteString(fmt.Sprintf("%-*s  ", widths[i], h))
	}
	c := color.New(color.FgHiBlack)
	c.Println(hdr.String())

	// Print rows
	for _, row := range rows {
		fmt.Print("  ")
		for i, cell := range row {
			if i < len(widths) {
				fmt.Printf("%-*s  ", widths[i], cell)
			}
		}
		fmt.Println()
	}
	fmt.Println()
}

func (p *Printer) Confirm(prompt string) bool {
	fmt.Printf("  %s [y/N] ", prompt)
	reader := bufio.NewReader(os.Stdin)
	line, _ := reader.ReadString('\n')
	line = strings.TrimSpace(strings.ToLower(line))
	return line == "y" || line == "yes"
}
