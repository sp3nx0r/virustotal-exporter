package main

import (
	"flag"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func unsetenv(t *testing.T, key string) {
	t.Helper()
	orig, ok := os.LookupEnv(key)
	if err := os.Unsetenv(key); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if !ok {
			_ = os.Unsetenv(key)
			return
		}
		_ = os.Setenv(key, orig)
	})
}

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
	unsetenv(t, "VT_EXPORTER_WEB_LISTEN_ADDRESS_FILE")
	unsetenv(t, "VT_EXPORTER_POLL_INTERVAL_FILE")
	unsetenv(t, "VT_EXPORTER_VT_BASE_URL_FILE")
	unsetenv(t, "VT_EXPORTER_VT_INCLUDE_REGULAR_USERS_FILE")

	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	if err := applyEnvDefaults(fs, "VT_EXPORTER_", log); err != nil {
		t.Fatalf("applyEnvDefaults: %v", err)
	}

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
	unsetenv(t, "VT_EXPORTER_POLL_INTERVAL_FILE")

	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	if err := applyEnvDefaults(fs, "VT_EXPORTER_", log); err != nil {
		t.Fatalf("applyEnvDefaults: %v", err)
	}

	if *interval != 60*time.Second {
		t.Errorf("invalid env value should keep default, got %v", *interval)
	}
}

func TestApplyEnvDefaultsFileWinsOverEnv(t *testing.T) {
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	groups := fs.String("vt.groups", "", "")
	interval := fs.Duration("poll.interval", 60*time.Second, "")
	if err := fs.Parse(nil); err != nil {
		t.Fatalf("parse: %v", err)
	}

	dir := t.TempDir()
	groupsPath := filepath.Join(dir, "groups")
	intervalPath := filepath.Join(dir, "interval")
	if err := os.WriteFile(groupsPath, []byte("from-file\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(intervalPath, []byte("10s\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	t.Setenv("VT_EXPORTER_VT_GROUPS", "from-env")
	t.Setenv("VT_EXPORTER_VT_GROUPS_FILE", groupsPath)
	t.Setenv("VT_EXPORTER_POLL_INTERVAL", "5s")
	t.Setenv("VT_EXPORTER_POLL_INTERVAL_FILE", intervalPath)

	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	if err := applyEnvDefaults(fs, "VT_EXPORTER_", log); err != nil {
		t.Fatalf("applyEnvDefaults: %v", err)
	}

	if *groups != "from-file" {
		t.Errorf("file should win over env: got %q, want from-file", *groups)
	}
	if *interval != 10*time.Second {
		t.Errorf("file duration should win over env: got %v, want 10s", *interval)
	}
}

func TestApplyEnvDefaultsCLIWinsOverFile(t *testing.T) {
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	groups := fs.String("vt.groups", "", "")
	if err := fs.Parse([]string{"-vt.groups=from-cli"}); err != nil {
		t.Fatalf("parse: %v", err)
	}

	path := filepath.Join(t.TempDir(), "groups")
	if err := os.WriteFile(path, []byte("from-file\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("VT_EXPORTER_VT_GROUPS_FILE", path)

	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	if err := applyEnvDefaults(fs, "VT_EXPORTER_", log); err != nil {
		t.Fatalf("applyEnvDefaults: %v", err)
	}

	if *groups != "from-cli" {
		t.Errorf("CLI flag should win over file: got %q, want from-cli", *groups)
	}
}

func TestApplyEnvDefaultsMissingFile(t *testing.T) {
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	_ = fs.String("vt.groups", "", "")
	if err := fs.Parse(nil); err != nil {
		t.Fatalf("parse: %v", err)
	}

	t.Setenv("VT_EXPORTER_VT_GROUPS_FILE", filepath.Join(t.TempDir(), "missing"))

	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	if err := applyEnvDefaults(fs, "VT_EXPORTER_", log); err == nil {
		t.Fatal("expected error for missing *_FILE path")
	}
}

func TestValueFromEnvOrFile(t *testing.T) {
	t.Run("neither", func(t *testing.T) {
		unsetenv(t, "VT_API_KEY")
		unsetenv(t, "VT_API_KEY_FILE")

		v, ok, err := valueFromEnvOrFile("VT_API_KEY")
		if err != nil {
			t.Fatalf("unexpected err: %v", err)
		}
		if ok {
			t.Fatalf("ok=true, value=%q", v)
		}
	})

	t.Run("env only", func(t *testing.T) {
		t.Setenv("VT_API_KEY", "from-env")
		unsetenv(t, "VT_API_KEY_FILE")

		v, ok, err := valueFromEnvOrFile("VT_API_KEY")
		if err != nil {
			t.Fatalf("unexpected err: %v", err)
		}
		if !ok || v != "from-env" {
			t.Fatalf("got ok=%v value=%q, want from-env", ok, v)
		}
	})

	t.Run("file wins over env", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "key")
		if err := os.WriteFile(path, []byte("from-file\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		t.Setenv("VT_API_KEY", "from-env")
		t.Setenv("VT_API_KEY_FILE", path)

		v, ok, err := valueFromEnvOrFile("VT_API_KEY")
		if err != nil {
			t.Fatalf("unexpected err: %v", err)
		}
		if !ok || v != "from-file" {
			t.Fatalf("got ok=%v value=%q, want from-file", ok, v)
		}
	})

	t.Run("empty file path", func(t *testing.T) {
		t.Setenv("VT_API_KEY_FILE", "   ")
		_, _, err := valueFromEnvOrFile("VT_API_KEY")
		if err == nil {
			t.Fatal("expected error for empty *_FILE path")
		}
	})

	t.Run("missing file", func(t *testing.T) {
		t.Setenv("VT_API_KEY_FILE", filepath.Join(t.TempDir(), "missing"))
		_, _, err := valueFromEnvOrFile("VT_API_KEY")
		if err == nil {
			t.Fatal("expected error for missing file")
		}
	})
}
