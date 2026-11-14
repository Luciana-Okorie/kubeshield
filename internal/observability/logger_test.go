package observability

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"strings"
	"testing"
)

func TestNewLoggerProductionEmitsJSON(t *testing.T) {
	var buf bytes.Buffer
	NewLogger("production", slog.LevelInfo, &buf).Info("hello", "k", "v")

	var rec map[string]any
	if err := json.Unmarshal(buf.Bytes(), &rec); err != nil {
		t.Fatalf("output is not JSON: %v\n%s", err, buf.String())
	}
	if rec["msg"] != "hello" || rec["k"] != "v" || rec["service"] != "kubeshield-api" {
		t.Errorf("unexpected record: %v", rec)
	}
}

func TestNewLoggerDevelopmentEmitsText(t *testing.T) {
	var buf bytes.Buffer
	NewLogger("development", slog.LevelInfo, &buf).Info("hello")

	if !strings.Contains(buf.String(), "msg=hello") {
		t.Errorf("expected text output, got %q", buf.String())
	}
}

func TestNewLoggerRespectsLevel(t *testing.T) {
	var buf bytes.Buffer
	NewLogger("development", slog.LevelWarn, &buf).Info("quiet")

	if buf.Len() != 0 {
		t.Errorf("info message logged at warn level: %q", buf.String())
	}
}
