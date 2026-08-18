## 1.1.0

Config can now be supplied from a **mounted file** as well as an environment
variable. Every env var the exporter already understands — `VT_API_KEY` and
each `VT_EXPORTER_*` flag mapping — has a companion `*_FILE` whose contents
are used instead. That lets Kubernetes/Docker secret volumes inject the API
key without putting it in the process environment.

Precedence is **CLI flag > `*_FILE` > env var > default**. File contents are
trimmed of surrounding whitespace (so a trailing newline in a secret file is
ignored). A missing or unreadable `*_FILE` path is a startup error; there is
no default mount path.

```bash
docker run --rm -p 9942:9942 \
  -e VT_API_KEY_FILE=/run/secrets/vt_api_key \
  -e VT_EXPORTER_VT_GROUPS_FILE=/run/secrets/vt_groups \
  -v /path/to/vt_api_key:/run/secrets/vt_api_key:ro \
  -v /path/to/vt_groups:/run/secrets/vt_groups:ro \
  ghcr.io/sp3nx0r/virustotal-exporter:1
```

The distroless image runs as uid 65532; mounted files must be readable by
that user. See the [README](README.md) for flags, PromQL examples, and the
Grafana dashboard.

---

## 1.0.0

First release of **virustotal-exporter**, a Prometheus exporter for VirusTotal
group API usage and quota data. It surfaces the same information the VirusTotal
UI shows under *Consumption* — overall usage, usage by resource/endpoint, and
usage by user (including service accounts) — plus quota limits.

### Features
- **Per-endpoint usage** (`vt_api_requests_total`) and **per-user usage**
  (`vt_user_api_requests_total`) as counters, so `rate()` gives sub-daily
  request rates despite VirusTotal only bucketing by calendar day.
- **Quota gauges** at group level (`vt_group_quota_used` / `_allowed`, incl.
  native hourly/daily/monthly) and per user (`vt_user_quota_used` / `_allowed`)
  to detect users hitting their own caps.
- **Service-account awareness** via `account_type`, with
  `-vt.include-regular-users=false` to cap cardinality.
- **Background poller** with keep-last-good caching and scrape-health metrics
  (`vt_scrape_success`, `vt_last_scrape_timestamp_seconds`, `vt_api_errors_total`).
- **Config via flags or env vars** (`VT_EXPORTER_*`), multi-group support.
- Multi-arch **distroless** container image and a starter Grafana dashboard.

### Install
```bash
docker run --rm -p 9942:9942 -e VT_API_KEY=... \
  ghcr.io/sp3nx0r/virustotal-exporter:1.0.0 -vt.groups=<your_group_id>
```
Requires a group-administrator API key. Quota-inspection endpoints don't consume
your VirusTotal quota. See the [README](README.md) for metrics, PromQL examples,
and the Grafana dashboard.

**Image:** `ghcr.io/sp3nx0r/virustotal-exporter:1.0.0` (`linux/amd64`, `linux/arm64`)
