package main

import (
	"flag"
	"io"
	"log/slog"
	"testing"
	"time"
)

func TestApplyEnvDefaults(t *testing.T) {
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	addr := fs.String("web.listen-address", ":9942", "")
	interval := fs.Duration("poll.interval", 60*time.Second, "")
	baseURL := fs.String("vt.base-url", "https://default", "")
	includeUsers := fs.Bool("vt.include-regular-users", true, "")

	// web.listen-address is provided on the CLI and must win over the env var.
	if err := fs.Parse([]string{"-web.listen-address=:1111"}); err != nil {
		t.Fatalf("parse: %v", err)
	}

	t.Setenv("VT_EXPORTER_WEB_LISTEN_ADDRESS", ":2222") // ignored: CLI wins
	t.Setenv("VT_EXPORTER_POLL_INTERVAL", "5s")
	t.Setenv("VT_EXPORTER_VT_BASE_URL", "https://env")
	t.Setenv("VT_EXPORTER_VT_INCLUDE_REGULAR_USERS", "false")

	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	applyEnvDefaults(fs, "VT_EXPORTER_", log)

	if *addr != ":1111" {
		t.Errorf("CLI flag should win: got %q, want :1111", *addr)
	}
	if *interval != 5*time.Second {
		t.Errorf("env duration not applied: got %v, want 5s", *interval)
	}
	if *baseURL != "https://env" {
		t.Errorf("env string not applied: got %q", *baseURL)
	}
	if *includeUsers {
		t.Errorf("env bool not applied: include-regular-users should be false")
	}
}

func TestApplyEnvDefaultsInvalidValueKeepsDefault(t *testing.T) {
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	interval := fs.Duration("poll.interval", 60*time.Second, "")
	if err := fs.Parse(nil); err != nil {
		t.Fatalf("parse: %v", err)
	}
	t.Setenv("VT_EXPORTER_POLL_INTERVAL", "not-a-duration")

	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	applyEnvDefaults(fs, "VT_EXPORTER_", log)

	if *interval != 60*time.Second {
		t.Errorf("invalid env value should keep default, got %v", *interval)
	}
}
