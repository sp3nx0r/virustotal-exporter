// Command virustotal-exporter is a Prometheus exporter for VirusTotal group API
// usage and quota data.
package main

import (
	"context"
	"errors"
	"flag"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/sp3nx0r/virustotal-exporter/internal/collector"
	"github.com/sp3nx0r/virustotal-exporter/internal/vt"
)

// version is set at build time via -ldflags "-X main.version=...".
var version = "dev"

func main() {
	var (
		listenAddr     = flag.String("web.listen-address", ":9942", "Address to listen on for telemetry.")
		metricsPath    = flag.String("web.telemetry-path", "/metrics", "Path under which to expose metrics.")
		groupsFlag     = flag.String("vt.groups", "", "Comma-separated VirusTotal group IDs to monitor (required).")
		baseURL        = flag.String("vt.base-url", vt.DefaultBaseURL, "VirusTotal API base URL.")
		pollInterval   = flag.Duration("poll.interval", 60*time.Second, "How often to poll the VirusTotal API.")
		requestTimeout = flag.Duration("vt.timeout", 30*time.Second, "Per-request timeout for VirusTotal API calls.")
		includeUsers   = flag.Bool("vt.include-regular-users", true, "Export per-user metrics for non-service-account users (account_type=\"user\"). Set false to reduce cardinality; service accounts are always exported.")
	)
	flag.Parse()

	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))

	// Apply env-var fallbacks for any flag not set on the command line.
	// Precedence: CLI flag > env var > default.
	applyEnvDefaults(flag.CommandLine, "VT_EXPORTER_", log)

	apiKey := os.Getenv("VT_API_KEY")
	if apiKey == "" {
		log.Error("VT_API_KEY environment variable is required")
		os.Exit(1)
	}
	groups := splitAndTrim(*groupsFlag)
	if len(groups) == 0 {
		log.Error("at least one group is required via -vt.groups")
		os.Exit(1)
	}

	client := vt.New(*baseURL, apiKey, &http.Client{Timeout: *requestTimeout})
	poller := collector.NewPoller(client, groups, *pollInterval, log)

	var collectorOpts []collector.Option
	if !*includeUsers {
		collectorOpts = append(collectorOpts, collector.WithoutRegularUsers())
	}

	reg := prometheus.NewRegistry()
	reg.MustRegister(
		collectors.NewGoCollector(),
		collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
		poller.ErrorsCounter(),
		collector.New(poller, version, collectorOpts...),
	)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	go poller.Run(ctx)

	mux := http.NewServeMux()
	mux.Handle(*metricsPath, promhttp.HandlerFor(reg, promhttp.HandlerOpts{}))
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write([]byte(`<html><head><title>VirusTotal Exporter</title></head>` +
			`<body><h1>VirusTotal Exporter</h1><p><a href="` + *metricsPath + `">Metrics</a></p></body></html>`))
	})

	srv := &http.Server{
		Addr:         *listenAddr,
		Handler:      mux,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 60 * time.Second,
	}

	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
	}()

	log.Info("starting virustotal-exporter",
		"version", version, "listen", *listenAddr, "groups", groups, "interval", pollInterval.String())

	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Error("http server error", "err", err)
		os.Exit(1)
	}
	log.Info("shutdown complete")
}

// applyEnvDefaults sets each flag that was not provided on the command line from
// an environment variable named "<prefix><FLAG>", where the flag name is
// uppercased and dots/dashes are replaced with underscores (e.g. the flag
// "vt.base-url" maps to "VT_EXPORTER_VT_BASE_URL"). Command-line flags always
// take precedence over environment variables.
func applyEnvDefaults(fs *flag.FlagSet, prefix string, log *slog.Logger) {
	set := map[string]bool{}
	fs.Visit(func(f *flag.Flag) { set[f.Name] = true })

	repl := strings.NewReplacer(".", "_", "-", "_")
	fs.VisitAll(func(f *flag.Flag) {
		if set[f.Name] {
			return
		}
		env := prefix + repl.Replace(strings.ToUpper(f.Name))
		v, ok := os.LookupEnv(env)
		if !ok {
			return
		}
		// The stdlib flag package clobbers a flag's value to its zero value even
		// when Set returns a parse error, so capture the current (default) value
		// and restore it if the env value fails to parse.
		prev := f.Value.String()
		if err := fs.Set(f.Name, v); err != nil {
			log.Warn("ignoring invalid environment value for flag",
				"env", env, "flag", f.Name, "value", v, "err", err)
			_ = f.Value.Set(prev)
		}
	})
}

func splitAndTrim(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if t := strings.TrimSpace(p); t != "" {
			out = append(out, t)
		}
	}
	return out
}
