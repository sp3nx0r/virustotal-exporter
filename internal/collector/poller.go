package collector

import (
	"context"
	"log/slog"
	"strings"
	"sync/atomic"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/sp3nx0r/virustotal-exporter/internal/vt"
)

// apiClient is the subset of *vt.Client used by the poller (aids testing).
type apiClient interface {
	GroupQuotas(ctx context.Context, groupID string) (map[string]vt.Quota, error)
	APIUsage(ctx context.Context, groupID string, day time.Time) (*vt.APIUsage, error)
	UsersConsumingAPIDaily(ctx context.Context, groupID string, day time.Time) ([]vt.UserConsumption, error)
	ServiceAccounts(ctx context.Context, groupID string) (map[string]bool, error)
}

// Poller periodically fetches usage data for each configured group and caches
// the result in an atomically-swapped snapshot.
type Poller struct {
	client   apiClient
	groups   []string
	interval time.Duration
	log      *slog.Logger
	now      func() time.Time

	errors *prometheus.CounterVec
	cur    atomic.Pointer[snapshot]
}

// NewPoller constructs a Poller and seeds an empty snapshot.
func NewPoller(client apiClient, groups []string, interval time.Duration, log *slog.Logger) *Poller {
	if log == nil {
		log = slog.Default()
	}
	p := &Poller{
		client:   client,
		groups:   groups,
		interval: interval,
		log:      log,
		now:      time.Now,
		errors: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "vt_api_errors_total",
			Help: "Total number of VirusTotal API request errors, by group and endpoint.",
		}, []string{"group", "endpoint"}),
	}
	p.cur.Store(&snapshot{Groups: map[string]*groupSnapshot{}})
	return p
}

// ErrorsCounter exposes the API-error counter so it can be registered.
func (p *Poller) ErrorsCounter() *prometheus.CounterVec { return p.errors }

// Snapshot returns the current cached snapshot. It is safe for concurrent use:
// the snapshot is loaded atomically and stored snapshots are treated as
// immutable (never mutated in place), so the metrics collector may read it
// concurrently with the poll goroutine.
func (p *Poller) Snapshot() *snapshot { return p.cur.Load() }

// Run performs an immediate poll and then polls on the configured interval
// until ctx is cancelled.
func (p *Poller) Run(ctx context.Context) {
	p.PollOnce(ctx)
	t := time.NewTicker(p.interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			p.PollOnce(ctx)
		}
	}
}

// PollOnce polls every group once and swaps in a new snapshot. On a per-group
// failure the previous group's data is retained (keep-last-good) with its
// success flag set to false. It is safe for concurrent use with Snapshot; it
// builds a fresh snapshot and installs it with a single atomic store rather than
// mutating the currently published one.
func (p *Poller) PollOnce(ctx context.Context) {
	prev := p.cur.Load()
	next := &snapshot{Groups: make(map[string]*groupSnapshot, len(p.groups))}
	day := p.now().UTC()

	for _, g := range p.groups {
		gs, err := p.pollGroup(ctx, g, day)
		if err != nil {
			p.log.Error("poll group failed", "group", g, "err", err)
			if old := prev.Groups[g]; old != nil {
				stale := *old
				stale.ScrapeSuccess = false
				next.Groups[g] = &stale
			} else {
				next.Groups[g] = &groupSnapshot{Group: g, ScrapeSuccess: false}
			}
			continue
		}
		next.Groups[g] = gs
	}
	p.cur.Store(next)
}

func (p *Poller) pollGroup(ctx context.Context, group string, day time.Time) (*groupSnapshot, error) {
	start := p.now()

	quotas, err := p.client.GroupQuotas(ctx, group)
	if err != nil {
		p.errors.WithLabelValues(group, "groups").Inc()
		return nil, err
	}

	svc, err := p.client.ServiceAccounts(ctx, group)
	if err != nil {
		p.errors.WithLabelValues(group, "service_accounts").Inc()
		return nil, err
	}

	usage, err := p.client.APIUsage(ctx, group, day)
	if err != nil {
		p.errors.WithLabelValues(group, "api_usage").Inc()
		return nil, err
	}

	users, err := p.client.UsersConsumingAPIDaily(ctx, group, day)
	if err != nil {
		p.errors.WithLabelValues(group, "users_consuming_quota").Inc()
		return nil, err
	}

	gs := &groupSnapshot{
		Group:          group,
		Quotas:         quotas,
		ScrapeSuccess:  true,
		LastScrape:     p.now(),
		ScrapeDuration: p.now().Sub(start),
	}
	for ep, n := range usage.Total {
		gs.Endpoints = append(gs.Endpoints, endpointUsage{Endpoint: normalizeEndpoint(ep), QuotaConsuming: true, Count: n})
	}
	for ep, n := range usage.TotalNonConsuming {
		gs.Endpoints = append(gs.Endpoints, endpointUsage{Endpoint: normalizeEndpoint(ep), QuotaConsuming: false, Count: n})
	}
	for _, u := range users {
		gs.Users = append(gs.Users, userUsage{
			User:           u.ID,
			ServiceAccount: svc[u.ID],
			Count:          u.Count,
			Quotas:         u.Quotas,
		})
	}
	return gs, nil
}

// normalizeEndpoint turns a raw key like "/api/v3/(file_download)" into
// "file_download". Unrecognized shapes are returned unchanged.
func normalizeEndpoint(raw string) string {
	open := strings.IndexByte(raw, '(')
	closeIdx := strings.LastIndexByte(raw, ')')
	if open >= 0 && closeIdx > open {
		return raw[open+1 : closeIdx]
	}
	return raw
}
