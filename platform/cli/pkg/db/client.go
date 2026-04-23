package db

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

type Client struct {
	pool *pgxpool.Pool
}

type SessionQuery struct {
	LiveOnly bool
	Severity string
	Decoy    string
	Since    string
	Limit    int
}

type SessionRow struct {
	SessionID string   `json:"sessionId"`
	DecoyName string   `json:"decoyName"`
	SourceIP  string   `json:"sourceIP"`
	Country   string   `json:"country"`
	Username  string   `json:"username"`
	StartTime string   `json:"startTime"`
	Commands  int      `json:"commandCount"`
	Severity  string   `json:"maxSeverity"`
	Phase     string   `json:"attackPhase"`
	Tools     []string `json:"toolsDetected"`
	Live      bool     `json:"live"`
}

type SessionEvent struct {
	Timestamp      string `json:"timestamp"`
	EventType      string `json:"eventType"`
	SourceIP       string `json:"sourceIP,omitempty"`
	Username       string `json:"username,omitempty"`
	Command        string `json:"command,omitempty"`
	Response       string `json:"response,omitempty"`
	Severity       string `json:"severity,omitempty"`
	MITRETechnique string `json:"mitreTechnique,omitempty"`
	MITREName      string `json:"mitreName,omitempty"`
}

type IOCRow struct {
	Type       string   `json:"type"`
	Value      string   `json:"value"`
	Severity   string   `json:"severity"`
	Confidence int      `json:"confidence"`
	Sightings  int      `json:"sightings"`
	FirstSeen  string   `json:"firstSeen"`
	LastSeen   string   `json:"lastSeen"`
	Techniques []string `json:"techniques"`
}

type ActorRow struct {
	SourceIP   string   `json:"sourceIP"`
	Country    string   `json:"country"`
	Sessions   int      `json:"sessions"`
	Commands   int      `json:"commands"`
	Severity   string   `json:"maxSeverity"`
	Techniques []string `json:"techniques"`
	FirstSeen  string   `json:"firstSeen"`
	LastSeen   string   `json:"lastSeen"`
}

type MITRETechRow struct {
	TechniqueID string `json:"techniqueId"`
	Name        string `json:"name"`
	Count       int    `json:"count"`
}

type HoneytokenRow struct {
	Name        string `json:"name"`
	Type        string `json:"type"`
	Decoy       string `json:"decoy"`
	Triggered   int    `json:"triggered"`
	LastTrigger string `json:"lastTrigger"`
	SourceIP    string `json:"sourceIP"`
}

func NewClient(dsn string) (*Client, error) {
	pool, err := pgxpool.New(context.Background(), dsn)
	if err != nil {
		return nil, fmt.Errorf("connecting to database: %w", err)
	}
	if err := pool.Ping(context.Background()); err != nil {
		return nil, fmt.Errorf("pinging database: %w", err)
	}
	return &Client{pool: pool}, nil
}

func (c *Client) Close() {
	c.pool.Close()
}

const maxQueryLimit = 10000

func capLimit(limit int) int {
	if limit <= 0 || limit > maxQueryLimit {
		return maxQueryLimit
	}
	return limit
}

func parseDuration(s string) time.Duration {
	s = strings.TrimSpace(s)
	if strings.HasSuffix(s, "d") {
		days := strings.TrimSuffix(s, "d")
		var n int
		fmt.Sscanf(days, "%d", &n)
		if n > 0 {
			return time.Duration(n) * 24 * time.Hour
		}
		return 24 * time.Hour
	}
	d, _ := time.ParseDuration(s)
	if d == 0 {
		d = 24 * time.Hour
	}
	return d
}

func (c *Client) ListSessions(ctx context.Context, q SessionQuery) ([]SessionRow, error) {
	since := time.Now().Add(-parseDuration(q.Since))
	limit := capLimit(q.Limit)
	if limit <= 0 {
		limit = 50
	}

	query := `
		SELECT session_id, decoy_name, source_ip::text, 
		       COALESCE((raw_data->>'username'), ''),
		       MIN(timestamp), COUNT(*),
		       MAX(severity),
		       COALESCE((SELECT jsonb_agg(DISTINCT t->>'tactic') 
		                 FROM decoy_events e2, jsonb_array_elements(e2.mitre_techniques) t
		                 WHERE e2.session_id = decoy_events.session_id), '[]')
		FROM decoy_events
		WHERE timestamp > $1
	`
	args := []interface{}{since}
	argIdx := 2

	if q.Decoy != "" {
		query += fmt.Sprintf(" AND decoy_name = $%d", argIdx)
		args = append(args, q.Decoy)
		argIdx++
	}
	if q.Severity != "" {
		query += fmt.Sprintf(" AND severity >= $%d", argIdx)
		args = append(args, q.Severity)
		argIdx++
	}

	query += ` GROUP BY session_id, decoy_name, source_ip, raw_data->>'username'
	           ORDER BY MIN(timestamp) DESC LIMIT $` + fmt.Sprintf("%d", argIdx)
	args = append(args, limit)

	rows, err := c.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var result []SessionRow
	for rows.Next() {
		var s SessionRow
		var startTime time.Time
		var tacticsJSON string
		err := rows.Scan(&s.SessionID, &s.DecoyName, &s.SourceIP, &s.Username,
			&startTime, &s.Commands, &s.Severity, &tacticsJSON)
		if err != nil {
			log.Printf("warning: skipping row due to scan error: %v", err)
			continue
		}
		s.StartTime = startTime.Format(time.RFC3339)
		if err := json.Unmarshal([]byte(tacticsJSON), &s.Tools); err != nil {
			log.Printf("warning: invalid tools JSON for session %s: %v", s.SessionID, err)
		}
		result = append(result, s)
	}
	return result, nil
}

func (c *Client) GetSessionEvents(ctx context.Context, sessionID string) ([]SessionEvent, error) {
	rows, err := c.pool.Query(ctx, `
		SELECT timestamp, event_type, COALESCE(source_ip::text, ''),
		       COALESCE(raw_data->>'username', ''),
		       COALESCE(raw_data->>'command', ''),
		       COALESCE(raw_data->>'response', ''),
		       COALESCE(severity, 'info'),
		       COALESCE(mitre_techniques->0->>'technique_id', ''),
		       COALESCE(mitre_techniques->0->>'technique_name', '')
		FROM decoy_events
		WHERE session_id = $1 OR session_id LIKE $2
		ORDER BY timestamp ASC
	`, sessionID, sessionID+"%")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var result []SessionEvent
	for rows.Next() {
		var e SessionEvent
		var ts time.Time
		if err := rows.Scan(&ts, &e.EventType, &e.SourceIP, &e.Username,
			&e.Command, &e.Response, &e.Severity, &e.MITRETechnique, &e.MITREName); err != nil {
			log.Printf("warning: skipping row due to scan error: %v", err)
			continue
		}
		e.Timestamp = ts.Format(time.RFC3339Nano)
		result = append(result, e)
	}
	return result, nil
}

func (c *Client) ListIOCs(ctx context.Context, iocType, severity, since string) ([]IOCRow, error) {
	sinceTime := time.Now().Add(-parseDuration(since))

	rows, err := c.pool.Query(ctx, `
		SELECT source_ip::text, COUNT(DISTINCT session_id), MAX(severity),
		       MIN(timestamp), MAX(timestamp),
		       jsonb_agg(DISTINCT mitre_techniques->0->>'technique_id')
		FROM decoy_events
		WHERE timestamp > $1 AND source_ip IS NOT NULL
		GROUP BY source_ip
		ORDER BY COUNT(*) DESC
		LIMIT 100
	`, sinceTime)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var result []IOCRow
	for rows.Next() {
		var r IOCRow
		var firstSeen, lastSeen time.Time
		var techJSON string
		if err := rows.Scan(&r.Value, &r.Sightings, &r.Severity, &firstSeen, &lastSeen, &techJSON); err != nil {
			log.Printf("warning: skipping row due to scan error: %v", err)
			continue
		}
		r.Type = "ip"
		r.Confidence = 80
		r.FirstSeen = firstSeen.Format("2006-01-02")
		r.LastSeen = lastSeen.Format("2006-01-02")
		if err := json.Unmarshal([]byte(techJSON), &r.Techniques); err != nil {
			log.Printf("warning: invalid techniques JSON for IOC %s: %v", r.Value, err)
		}
		// Filter out nulls
		var clean []string
		for _, t := range r.Techniques {
			if t != "" {
				clean = append(clean, t)
			}
		}
		r.Techniques = clean
		result = append(result, r)
	}
	return result, nil
}

func (c *Client) ListActors(ctx context.Context, since string, minSessions int) ([]ActorRow, error) {
	sinceTime := time.Now().Add(-parseDuration(since))

	rows, err := c.pool.Query(ctx, `
		SELECT source_ip::text, COUNT(DISTINCT session_id), COUNT(*),
		       MAX(severity), MIN(timestamp), MAX(timestamp),
		       COALESCE((geo->>'country'), ''),
		       jsonb_agg(DISTINCT mitre_techniques->0->>'technique_id')
		FROM decoy_events
		WHERE timestamp > $1 AND source_ip IS NOT NULL
		GROUP BY source_ip, geo->>'country'
		HAVING COUNT(DISTINCT session_id) >= $2
		ORDER BY COUNT(DISTINCT session_id) DESC
		LIMIT 50
	`, sinceTime, minSessions)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var result []ActorRow
	for rows.Next() {
		var a ActorRow
		var firstSeen, lastSeen time.Time
		var techJSON string
		if err := rows.Scan(&a.SourceIP, &a.Sessions, &a.Commands, &a.Severity,
			&firstSeen, &lastSeen, &a.Country, &techJSON); err != nil {
			log.Printf("warning: skipping row due to scan error: %v", err)
			continue
		}
		a.FirstSeen = firstSeen.Format("2006-01-02")
		a.LastSeen = lastSeen.Format("2006-01-02")
		if err := json.Unmarshal([]byte(techJSON), &a.Techniques); err != nil {
			log.Printf("warning: invalid techniques JSON for actor %s: %v", a.SourceIP, err)
		}
		result = append(result, a)
	}
	return result, nil
}

func (c *Client) MITRESummary(ctx context.Context, since string) ([]MITRETechRow, error) {
	sinceTime := time.Now().Add(-parseDuration(since))

	rows, err := c.pool.Query(ctx, `
		SELECT t->>'technique_id', t->>'technique_name', COUNT(*)
		FROM decoy_events, jsonb_array_elements(mitre_techniques) t
		WHERE timestamp > $1 AND jsonb_array_length(mitre_techniques) > 0
		GROUP BY t->>'technique_id', t->>'technique_name'
		ORDER BY COUNT(*) DESC
		LIMIT 30
	`, sinceTime)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var result []MITRETechRow
	for rows.Next() {
		var r MITRETechRow
		if err := rows.Scan(&r.TechniqueID, &r.Name, &r.Count); err != nil {
			log.Printf("warning: skipping row due to scan error: %v", err)
			continue
		}
		result = append(result, r)
	}
	return result, nil
}

func (c *Client) ListHoneytokens(ctx context.Context, triggered bool, since string) ([]HoneytokenRow, error) {
	// Query from decoy_events where event_type = 'honeytoken.triggered'
	sinceTime := time.Now().Add(-parseDuration(since))

	rows, err := c.pool.Query(ctx, `
		SELECT COALESCE(raw_data->>'token_name', ''), COALESCE(raw_data->>'token_type', ''),
		       decoy_name, COUNT(*), MAX(timestamp), COALESCE(source_ip::text, '')
		FROM decoy_events
		WHERE event_type = 'honeytoken.triggered' AND timestamp > $1
		GROUP BY raw_data->>'token_name', raw_data->>'token_type', decoy_name, source_ip
		ORDER BY MAX(timestamp) DESC
	`, sinceTime)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var result []HoneytokenRow
	for rows.Next() {
		var h HoneytokenRow
		var lastTrigger time.Time
		if err := rows.Scan(&h.Name, &h.Type, &h.Decoy, &h.Triggered, &lastTrigger, &h.SourceIP); err != nil {
			log.Printf("warning: skipping row due to scan error: %v", err)
			continue
		}
		h.LastTrigger = lastTrigger.Format("2006-01-02 15:04")
		result = append(result, h)
	}
	return result, nil
}

func (c *Client) RecentEvents(ctx context.Context, decoy, eventType, since string, limit int) ([]SessionEvent, error) {
	limit = capLimit(limit)
	sinceTime := time.Now().Add(-parseDuration(since))

	query := `
		SELECT timestamp, event_type, COALESCE(source_ip::text, ''),
		       COALESCE(raw_data->>'username', ''),
		       COALESCE(raw_data->>'command', ''),
		       '', COALESCE(severity, 'info'), '', ''
		FROM decoy_events
		WHERE decoy_name = $1 AND timestamp > $2
	`
	args := []interface{}{decoy, sinceTime}
	if eventType != "" {
		query += " AND event_type = $3"
		args = append(args, eventType)
	}
	query += fmt.Sprintf(" ORDER BY timestamp DESC LIMIT %d", limit)

	rows, err := c.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var result []SessionEvent
	for rows.Next() {
		var e SessionEvent
		var ts time.Time
		if err := rows.Scan(&ts, &e.EventType, &e.SourceIP, &e.Username,
			&e.Command, &e.Response, &e.Severity, &e.MITRETechnique, &e.MITREName); err != nil {
			log.Printf("warning: skipping row due to scan error: %v", err)
			continue
		}
		e.Timestamp = ts.Format("15:04:05")
		result = append(result, e)
	}
	return result, nil
}

func (c *Client) ExportIntel(ctx context.Context, format, since, until string) ([]byte, error) {
	iocs, err := c.ListIOCs(ctx, "", "", since)
	if err != nil {
		return nil, fmt.Errorf("listing IOCs: %w", err)
	}
	techniques, err := c.MITRESummary(ctx, since)
	if err != nil {
		return nil, fmt.Errorf("summarizing techniques: %w", err)
	}

	export := map[string]interface{}{
		"generated": time.Now().Format(time.RFC3339),
		"period":    since,
		"iocs":      iocs,
		"techniques": techniques,
	}
	return json.MarshalIndent(export, "", "  ")
}

func (c *Client) GenerateReport(ctx context.Context, period, format string) ([]byte, error) {
	since := "7d"
	switch period {
	case "daily":
		since = "1d"
	case "monthly":
		since = "30d"
	}

	iocs, err := c.ListIOCs(ctx, "", "", since)
	if err != nil {
		return nil, fmt.Errorf("listing IOCs: %w", err)
	}
	techniques, err := c.MITRESummary(ctx, since)
	if err != nil {
		return nil, fmt.Errorf("summarizing techniques: %w", err)
	}
	actors, err := c.ListActors(ctx, since, 1)
	if err != nil {
		return nil, fmt.Errorf("listing actors: %w", err)
	}

	var b strings.Builder
	b.WriteString(fmt.Sprintf("# CI/CDecoy Intelligence Report — %s\n\n", period))
	b.WriteString(fmt.Sprintf("Generated: %s\n\n", time.Now().Format("2006-01-02 15:04 MST")))

	b.WriteString("## Summary\n\n")
	b.WriteString(fmt.Sprintf("- **Unique source IPs**: %d\n", len(iocs)))
	b.WriteString(fmt.Sprintf("- **Unique actors**: %d\n", len(actors)))
	b.WriteString(fmt.Sprintf("- **MITRE techniques observed**: %d\n\n", len(techniques)))

	b.WriteString("## Top MITRE ATT&CK Techniques\n\n")
	b.WriteString("| Technique | Name | Count |\n|---|---|---|\n")
	for i, t := range techniques {
		if i >= 10 {
			break
		}
		b.WriteString(fmt.Sprintf("| %s | %s | %d |\n", t.TechniqueID, t.Name, t.Count))
	}

	b.WriteString("\n## Top Threat Actors\n\n")
	b.WriteString("| Source IP | Country | Sessions | Severity |\n|---|---|---|---|\n")
	for i, a := range actors {
		if i >= 10 {
			break
		}
		b.WriteString(fmt.Sprintf("| %s | %s | %d | %s |\n", a.SourceIP, a.Country, a.Sessions, a.Severity))
	}

	return []byte(b.String()), nil
}
