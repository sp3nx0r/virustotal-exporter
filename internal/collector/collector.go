// Package collector polls VirusTotal group usage/quota data and exposes it as
// Prometheus metrics via a custom collector emitting const metrics from an
// atomically-swapped snapshot.
package collector

import (
	"strconv"

	"github.com/prometheus/client_golang/prometheus"
)

var (
	descAPIRequests = prometheus.NewDesc(
		"vt_api_requests_total",
		"Cumulative VirusTotal API requests for the current UTC day, by endpoint. Emitted as a counter so rate() yields sub-daily request rates (resets to 0 at UTC midnight).",
		[]string{"group", "endpoint", "quota_consuming"}, nil,
	)
	descUserAPIRequests = prometheus.NewDesc(
		"vt_user_api_requests_total",
		"Cumulative VirusTotal API requests for the current UTC day, by user. Emitted as a counter (resets to 0 at UTC midnight).",
		[]string{"group", "user", "account_type"}, nil,
	)
	descQuotaUsed = prometheus.NewDesc(
		"vt_group_quota_used",
		"Consumed amount of a VirusTotal group quota (e.g. api_requests_hourly/daily/monthly).",
		[]string{"group", "quota"}, nil,
	)
	descQuotaAllowed = prometheus.NewDesc(
		"vt_group_quota_allowed",
		"Maximum allowed amount of a VirusTotal group quota.",
		[]string{"group", "quota"}, nil,
	)
	descUserQuotaUsed = prometheus.NewDesc(
		"vt_user_quota_used",
		"Consumed amount of a per-user VirusTotal quota. Compare with vt_user_quota_allowed to detect a user hitting their quota.",
		[]string{"group", "user", "quota"}, nil,
	)
	descUserQuotaAllowed = prometheus.NewDesc(
		"vt_user_quota_allowed",
		"Maximum allowed amount of a per-user VirusTotal quota. A very large value (e.g. 1e9) means no meaningful individual cap is set and only the shared group quota applies.",
		[]string{"group", "user", "quota"}, nil,
	)
	descScrapeSuccess = prometheus.NewDesc(
		"vt_scrape_success",
		"Whether the most recent poll of the group succeeded (1) or failed (0).",
		[]string{"group"}, nil,
	)
	descLastScrape = prometheus.NewDesc(
		"vt_last_scrape_timestamp_seconds",
		"Unix timestamp of the last successful poll of the group.",
		[]string{"group"}, nil,
	)
	descScrapeDuration = prometheus.NewDesc(
		"vt_scrape_duration_seconds",
		"Duration of the last successful poll of the group in seconds.",
		[]string{"group"}, nil,
	)
	descBuildInfo = prometheus.NewDesc(
		"vt_exporter_build_info",
		"Build information for the virustotal-exporter.",
		[]string{"version"}, nil,
	)
)

// Collector exposes the poller's snapshot as Prometheus metrics.
type Collector struct {
	src                 interface{ Snapshot() *snapshot }
	version             string
	includeRegularUsers bool
}

// Option configures a Collector.
type Option func(*Collector)

// WithoutRegularUsers drops per-user metrics for non-service-account users
// (account_type="user"), keeping only service accounts. Useful when the number
// of regular users would blow up metric cardinality.
func WithoutRegularUsers() Option {
	return func(c *Collector) { c.includeRegularUsers = false }
}

// New returns a Collector reading from the given snapshot source (a *Poller).
func New(src interface{ Snapshot() *snapshot }, version string, opts ...Option) *Collector {
	c := &Collector{src: src, version: version, includeRegularUsers: true}
	for _, opt := range opts {
		opt(c)
	}
	return c
}

// Describe implements prometheus.Collector.
func (c *Collector) Describe(ch chan<- *prometheus.Desc) {
	ch <- descAPIRequests
	ch <- descUserAPIRequests
	ch <- descQuotaUsed
	ch <- descQuotaAllowed
	ch <- descUserQuotaUsed
	ch <- descUserQuotaAllowed
	ch <- descScrapeSuccess
	ch <- descLastScrape
	ch <- descScrapeDuration
	ch <- descBuildInfo
}

// Collect implements prometheus.Collector.
func (c *Collector) Collect(ch chan<- prometheus.Metric) {
	ch <- prometheus.MustNewConstMetric(descBuildInfo, prometheus.GaugeValue, 1, c.version)

	snap := c.src.Snapshot()
	if snap == nil {
		return
	}
	for _, g := range snap.Groups {
		success := 0.0
		if g.ScrapeSuccess {
			success = 1.0
		}
		ch <- prometheus.MustNewConstMetric(descScrapeSuccess, prometheus.GaugeValue, success, g.Group)
		if !g.LastScrape.IsZero() {
			ch <- prometheus.MustNewConstMetric(descLastScrape, prometheus.GaugeValue, float64(g.LastScrape.Unix()), g.Group)
			ch <- prometheus.MustNewConstMetric(descScrapeDuration, prometheus.GaugeValue, g.ScrapeDuration.Seconds(), g.Group)
		}

		for _, e := range g.Endpoints {
			ch <- prometheus.MustNewConstMetric(
				descAPIRequests, prometheus.CounterValue, e.Count,
				g.Group, e.Endpoint, strconv.FormatBool(e.QuotaConsuming),
			)
		}
		for _, u := range g.Users {
			if !u.ServiceAccount && !c.includeRegularUsers {
				continue
			}
			accountType := "user"
			if u.ServiceAccount {
				accountType = "service_account"
			}
			ch <- prometheus.MustNewConstMetric(
				descUserAPIRequests, prometheus.CounterValue, u.Count,
				g.Group, u.User, accountType,
			)
			for name, q := range u.Quotas {
				ch <- prometheus.MustNewConstMetric(descUserQuotaUsed, prometheus.GaugeValue, q.Used, g.Group, u.User, name)
				ch <- prometheus.MustNewConstMetric(descUserQuotaAllowed, prometheus.GaugeValue, q.Allowed, g.Group, u.User, name)
			}
		}
		for name, q := range g.Quotas {
			ch <- prometheus.MustNewConstMetric(descQuotaUsed, prometheus.GaugeValue, q.Used, g.Group, name)
			ch <- prometheus.MustNewConstMetric(descQuotaAllowed, prometheus.GaugeValue, q.Allowed, g.Group, name)
		}
	}
}
