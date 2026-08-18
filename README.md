# virustotal-exporter

[![CI](https://github.com/sp3nx0r/virustotal-exporter/actions/workflows/ci.yml/badge.svg)](https://github.com/sp3nx0r/virustotal-exporter/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/sp3nx0r/virustotal-exporter?sort=semver)](https://github.com/sp3nx0r/virustotal-exporter/releases)
[![Go version](https://img.shields.io/github/go-mod/go-version/sp3nx0r/virustotal-exporter)](go.mod)
[![License: BSD-3-Clause](https://img.shields.io/badge/License-BSD_3--Clause-blue.svg)](LICENSE)

A Prometheus exporter for [VirusTotal](https://www.virustotal.com) **group API
usage and quota** data. It surfaces the same information the VirusTotal UI shows
under *Consumption* — overall usage, usage by resource/endpoint, and usage by
user (including service accounts) — plus the group's quota limits.

## What it exports

A background poller fetches from the VirusTotal v3 API on a fixed interval
(default 60s) and caches the result; `/metrics` serves the cache, so Prometheus
scrapes never hit VirusTotal directly.

| Metric | Type | Labels | Source |
| --- | --- | --- | --- |
| `vt_api_requests_total` | counter | `group`, `endpoint`, `quota_consuming` | `GET /groups/{id}/api_usage` (current UTC day) |
| `vt_user_api_requests_total` | counter | `group`, `user`, `account_type` | `GET /groups/{id}/users_consuming_quota/api_requests_daily` |
| `vt_group_quota_used` | gauge | `group`, `quota` | `GET /groups/{id}` `quotas` |
| `vt_group_quota_allowed` | gauge | `group`, `quota` | `GET /groups/{id}` `quotas` |
| `vt_user_quota_used` | gauge | `group`, `user`, `quota` | per-user `quotas` from `users_consuming_quota` |
| `vt_user_quota_allowed` | gauge | `group`, `user`, `quota` | per-user `quotas` from `users_consuming_quota` |
| `vt_scrape_success` | gauge | `group` | exporter |
| `vt_last_scrape_timestamp_seconds` | gauge | `group` | exporter |
| `vt_scrape_duration_seconds` | gauge | `group` | exporter |
| `vt_api_errors_total` | counter | `group`, `endpoint` | exporter |
| `vt_exporter_build_info` | gauge | `version` | exporter |

### Why the per-endpoint / per-user metrics are counters

VirusTotal only buckets per-endpoint and per-user usage by **calendar day**
(UTC). The exporter reports the day's *cumulative* count as a Prometheus
**counter**. Within a day the value only grows; at UTC midnight it drops to 0,
which Prometheus treats as a normal counter reset. This lets you recover
sub-daily resolution with `rate()`:

```promql
# overall request rate (per second), last 5m
sum(rate(vt_api_requests_total[5m]))

# request rate by endpoint
sum by (endpoint) (rate(vt_api_requests_total[5m]))

# request rate by user / service account
sum by (user, account_type) (rate(vt_user_api_requests_total[5m]))
```

The effective resolution equals your poll interval, bounded by how fresh
VirusTotal's `api_usage` data is. The **aggregate** quota counters
(`api_requests_hourly` / `daily` / `monthly`) come straight from the group's
enforcement quotas and are near-real-time:

```promql
# daily quota utilization (0..1)
vt_group_quota_used{quota="api_requests_daily"} / vt_group_quota_allowed{quota="api_requests_daily"}
```

### Detecting a user hitting their quota

VirusTotal's API quota is shared at the group level, but admins can also assign
per-user caps. `vt_user_quota_used` / `vt_user_quota_allowed` expose each user's
own limits:

```promql
# users who have hit their own daily quota
vt_user_quota_used{quota="api_requests_daily"} >= vt_user_quota_allowed{quota="api_requests_daily"}

# fraction of their own daily cap consumed
vt_user_quota_used{quota="api_requests_daily"} / vt_user_quota_allowed{quota="api_requests_daily"}
```

If no individual cap is set, VirusTotal returns a very large sentinel `allowed`
(e.g. `1e9`), so the first expression simply never fires — meaning only the
shared group quota applies to that user.

`account_type` is `service_account` for usernames returned by the group's
`service_accounts` relationship, else `user`. If the number of regular users
would blow up cardinality, run with `-vt.include-regular-users=false` to export
only service-account per-user metrics.

## Requirements

The API key must be a **group administrator** key for each group you monitor —
the `api_usage`, `users_consuming_quota`, and group `quotas` data are only
available to group admins. These quota-inspection endpoints do **not** consume
your API quota, so frequent polling is safe.

## Usage

```bash
export VT_API_KEY=your-group-admin-api-key
virustotal-exporter -vt.groups=your_group_id_here
```

### Flags

| Flag | Env var | Default | Description |
| --- | --- | --- | --- |
| `-vt.groups` | `VT_EXPORTER_VT_GROUPS` | *(required)* | Comma-separated VirusTotal group IDs to monitor. |
| `-vt.base-url` | `VT_EXPORTER_VT_BASE_URL` | `https://www.virustotal.com/api/v3` | VirusTotal API base URL. |
| `-poll.interval` | `VT_EXPORTER_POLL_INTERVAL` | `60s` | How often to poll the VirusTotal API. |
| `-vt.timeout` | `VT_EXPORTER_VT_TIMEOUT` | `30s` | Per-request timeout. |
| `-vt.include-regular-users` | `VT_EXPORTER_VT_INCLUDE_REGULAR_USERS` | `true` | Export per-user metrics for non-service-account users. Set `false` to drop `account_type="user"` series and reduce cardinality; service accounts are always exported. |
| `-web.listen-address` | `VT_EXPORTER_WEB_LISTEN_ADDRESS` | `:9942` | Address to expose telemetry on. |
| `-web.telemetry-path` | `VT_EXPORTER_WEB_TELEMETRY_PATH` | `/metrics` | Path under which to expose metrics. |

Every flag can also be set via its environment variable (naming convention:
`VT_EXPORTER_<FLAG>`, uppercased with `.`/`-` replaced by `_`). Any of those
env vars — and `VT_API_KEY` — can alternatively be read from a file by setting
`<ENV>_FILE` to a path (Docker/Kubernetes secret mounts). File contents are
trimmed of surrounding whitespace. Precedence is **CLI flag > `*_FILE` > env
var > default**. An invalid env/file value for a flag is logged and the default
is used; a missing or unreadable `*_FILE` path is a startup error.

`VT_API_KEY` is the API key and is never a flag. Provide it via `VT_API_KEY` or
`VT_API_KEY_FILE`. Fully env-driven invocation:

```bash
export VT_API_KEY=... VT_EXPORTER_VT_GROUPS=your_group_id_here VT_EXPORTER_POLL_INTERVAL=30s
virustotal-exporter
```

Or from mounted files (no default path — point `*_FILE` at wherever you mounted):

```bash
export VT_API_KEY_FILE=/run/secrets/vt_api_key
export VT_EXPORTER_VT_GROUPS_FILE=/mnt/secrets/vt_groups
virustotal-exporter
```

Endpoints: `/metrics`, `/healthz`, and a small landing page at `/`.

## Docker

Prebuilt multi-arch images are published to GHCR on each release:

```bash
docker run --rm -p 9942:9942 -e VT_API_KEY=... \
  ghcr.io/sp3nx0r/virustotal-exporter:1 -vt.groups=your_group_id_here
```

Tags follow semver: `1.2.3`, `1.2`, `1`, and `latest` (latest tracks the newest
non-prerelease release). To pass the key as a file instead of an env var
(Compose/Swarm secrets land at `/run/secrets/<name>`; Kubernetes CSI examples
often use `/mnt/secrets-store`):

```bash
docker run --rm -p 9942:9942 \
  -e VT_API_KEY_FILE=/run/secrets/vt_api_key \
  -v /path/to/vt_api_key:/run/secrets/vt_api_key:ro \
  ghcr.io/sp3nx0r/virustotal-exporter:1 -vt.groups=your_group_id_here
```

Or build locally:

```bash
docker build -t virustotal-exporter .
docker run --rm -p 9942:9942 -e VT_API_KEY=... virustotal-exporter -vt.groups=your_group_id_here
```

The image is built `FROM gcr.io/distroless/static:nonroot`. Mounted secret files
must be readable by uid 65532.

## Releasing

CI (`.github/workflows/ci.yml`) runs gofmt/vet/build/`go test -race` plus a
no-push Docker build on every push and PR. Pushing a semver tag triggers
`.github/workflows/release.yml`, which builds a multi-arch image
(`linux/amd64`, `linux/arm64`) and pushes it to GHCR with the version baked into
`vt_exporter_build_info`.

```bash
git tag v1.0.0
git push origin v1.0.0
```

## Prometheus & Grafana

- Example scrape config: [`examples/prometheus.yml`](examples/prometheus.yml)
- Starter dashboard: [`examples/grafana-dashboard.json`](examples/grafana-dashboard.json)

## Development

```bash
make vet test build     # or: go test ./...
```

Tests mock the VirusTotal API with `httptest` and JSON fixtures under
`internal/collector/testdata`; no network calls or secrets required.

### Verify data freshness against the live API

Before relying on sub-daily `rate()` for per-endpoint/per-user metrics, confirm
how quickly VirusTotal updates `api_usage`. Hit it a couple of times a minute
apart and watch the numbers move:

```bash
curl -s -H "x-apikey: $VT_API_KEY" \
  "https://www.virustotal.com/api/v3/groups/<GROUP>/api_usage?start_date=$(date -u +%Y%m%d)&end_date=$(date -u +%Y%m%d)" | jq .
```

If those per-endpoint numbers update promptly, sub-daily `rate()` is meaningful.
If they batch/lag, rely on `vt_group_quota_used{quota="api_requests_hourly"}` for
real-time aggregate usage and treat the per-endpoint/per-user series as trend.

## License

[BSD-3-Clause](LICENSE).
