package collector

import (
	"time"

	"github.com/sp3nx0r/virustotal-exporter/internal/vt"
)

// endpointUsage is one normalized per-endpoint usage record for a UTC day.
type endpointUsage struct {
	Endpoint       string
	QuotaConsuming bool
	Count          float64
}

// userUsage is one per-user usage record for a UTC day.
type userUsage struct {
	User           string
	ServiceAccount bool
	Count          float64
	Quotas         map[string]vt.Quota
}

// groupSnapshot holds the last-known state for a single group.
type groupSnapshot struct {
	Group          string
	Endpoints      []endpointUsage
	Users          []userUsage
	Quotas         map[string]vt.Quota
	ScrapeSuccess  bool
	LastScrape     time.Time
	ScrapeDuration time.Duration
}

// snapshot is the immutable, atomically-swapped view served to Prometheus.
type snapshot struct {
	Groups map[string]*groupSnapshot
}
