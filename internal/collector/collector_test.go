package collector

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/sp3nx0r/virustotal-exporter/internal/vt"
)

var fixedNow = time.Date(2026, 7, 30, 12, 0, 0, 0, time.UTC)

func fixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("reading fixture %s: %v", name, err)
	}
	return b
}

// vtTestServer routes the VT endpoints to fixtures, paginating the users endpoint.
func vtTestServer(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("x-apikey") == "" {
			http.Error(w, `{"error":{"code":"AuthenticationRequiredError"}}`, http.StatusUnauthorized)
			return
		}
		p := r.URL.Path
		w.Header().Set("Content-Type", "application/json")
		switch {
		case strings.HasSuffix(p, "/api_usage"):
			_, _ = w.Write(fixture(t, "api_usage.json"))
		case strings.Contains(p, "/users_consuming_quota/"):
			if r.URL.Query().Get("cursor") == "PAGE2" {
				_, _ = w.Write(fixture(t, "users_page2.json"))
			} else {
				_, _ = w.Write(fixture(t, "users_page1.json"))
			}
		case strings.HasSuffix(p, "/relationships/service_accounts"):
			_, _ = w.Write(fixture(t, "service_accounts.json"))
		case strings.HasPrefix(p, "/groups/"):
			_, _ = w.Write(fixture(t, "group.json"))
		default:
			http.NotFound(w, r)
		}
	}))
}

func gatherMap(t *testing.T, g prometheus.Gatherer) map[string]float64 {
	t.Helper()
	mfs, err := g.Gather()
	if err != nil {
		t.Fatalf("gather: %v", err)
	}
	out := map[string]float64{}
	for _, mf := range mfs {
		for _, m := range mf.Metric {
			var lbls []string
			for _, lp := range m.Label {
				lbls = append(lbls, lp.GetName()+"="+lp.GetValue())
			}
			sort.Strings(lbls)
			key := mf.GetName() + "{" + strings.Join(lbls, ",") + "}"
			switch {
			case m.Counter != nil:
				out[key] = m.Counter.GetValue()
			case m.Gauge != nil:
				out[key] = m.Gauge.GetValue()
			}
		}
	}
	return out
}

func TestPollAndCollect(t *testing.T) {
	srv := vtTestServer(t)
	defer srv.Close()

	client := vt.New(srv.URL, "test-key", srv.Client())
	poller := NewPoller(client, []string{"your_group_id_here"}, time.Minute, nil)
	poller.now = func() time.Time { return fixedNow }
	poller.PollOnce(context.Background())

	reg := prometheus.NewRegistry()
	reg.MustRegister(poller.ErrorsCounter(), New(poller, "test"))

	got := gatherMap(t, reg)

	want := map[string]float64{
		`vt_api_requests_total{endpoint=file_download,group=your_group_id_here,quota_consuming=true}`:                               87,
		`vt_api_requests_total{endpoint=domains,group=your_group_id_here,quota_consuming=true}`:                                     6,
		`vt_api_requests_total{endpoint=files,group=your_group_id_here,quota_consuming=false}`:                                      100,
		`vt_user_api_requests_total{account_type=service_account,group=your_group_id_here,user=your_group_id_here_service_account}`: 93,
		`vt_user_api_requests_total{account_type=user,group=your_group_id_here,user=alice}`:                                         6,
		`vt_group_quota_used{group=your_group_id_here,quota=api_requests_daily}`:                                                    93,
		`vt_group_quota_allowed{group=your_group_id_here,quota=api_requests_daily}`:                                                 1000,
		`vt_group_quota_used{group=your_group_id_here,quota=api_requests_hourly}`:                                                   5,
		`vt_group_quota_allowed{group=your_group_id_here,quota=api_requests_hourly}`:                                                60000,
		`vt_group_quota_used{group=your_group_id_here,quota=api_requests_monthly}`:                                                  68,
		`vt_group_quota_allowed{group=your_group_id_here,quota=api_requests_monthly}`:                                               30000,
		`vt_user_quota_used{group=your_group_id_here,quota=api_requests_daily,user=your_group_id_here_service_account}`:             93,
		`vt_user_quota_allowed{group=your_group_id_here,quota=api_requests_daily,user=your_group_id_here_service_account}`:          5000,
		`vt_user_quota_used{group=your_group_id_here,quota=api_requests_daily,user=alice}`:                                          6,
		`vt_user_quota_allowed{group=your_group_id_here,quota=api_requests_daily,user=alice}`:                                       100,
		`vt_scrape_success{group=your_group_id_here}`:                                                                               1,
		`vt_last_scrape_timestamp_seconds{group=your_group_id_here}`:                                                                float64(fixedNow.Unix()),
		`vt_exporter_build_info{version=test}`:                                                                                      1,
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("metric %s = %v, want %v", k, got[k], v)
		}
	}
}

func TestWithoutRegularUsers(t *testing.T) {
	srv := vtTestServer(t)
	defer srv.Close()

	client := vt.New(srv.URL, "test-key", srv.Client())
	poller := NewPoller(client, []string{"your_group_id_here"}, time.Minute, nil)
	poller.now = func() time.Time { return fixedNow }
	poller.PollOnce(context.Background())

	reg := prometheus.NewRegistry()
	reg.MustRegister(New(poller, "test", WithoutRegularUsers()))

	got := gatherMap(t, reg)

	// Service accounts are still exported.
	saKey := `vt_user_api_requests_total{account_type=service_account,group=your_group_id_here,user=your_group_id_here_service_account}`
	if got[saKey] != 93 {
		t.Errorf("service account metric = %v, want 93", got[saKey])
	}
	// Regular users are dropped, including their per-user quota series.
	for _, userKey := range []string{
		`vt_user_api_requests_total{account_type=user,group=your_group_id_here,user=alice}`,
		`vt_user_quota_used{group=your_group_id_here,quota=api_requests_daily,user=alice}`,
		`vt_user_quota_allowed{group=your_group_id_here,quota=api_requests_daily,user=alice}`,
	} {
		if _, ok := got[userKey]; ok {
			t.Errorf("expected regular-user metric to be dropped, but found %s", userKey)
		}
	}
	// Service-account quota series is retained.
	if got[`vt_user_quota_allowed{group=your_group_id_here,quota=api_requests_daily,user=your_group_id_here_service_account}`] != 5000 {
		t.Errorf("expected service-account quota to be retained")
	}
}

func TestNormalizeEndpoint(t *testing.T) {
	cases := map[string]string{
		"/api/v3/(file_download)":       "file_download",
		"/api/v3/(intelligence_search)": "intelligence_search",
		"plain":                         "plain",
		"":                              "",
	}
	for in, want := range cases {
		if got := normalizeEndpoint(in); got != want {
			t.Errorf("normalizeEndpoint(%q) = %q, want %q", in, got, want)
		}
	}
}

// flakyClient succeeds on the first poll then fails, to exercise keep-last-good.
type flakyClient struct {
	calls int
}

func (f *flakyClient) fail() bool { f.calls++; return f.calls > 1 }

func (f *flakyClient) GroupQuotas(context.Context, string) (map[string]vt.Quota, error) {
	if f.fail() {
		return nil, errors.New("boom")
	}
	return map[string]vt.Quota{"api_requests_daily": {Allowed: 1000, Used: 42}}, nil
}
func (f *flakyClient) APIUsage(context.Context, string, time.Time) (*vt.APIUsage, error) {
	return &vt.APIUsage{Total: map[string]float64{"/api/v3/(files)": 10}}, nil
}
func (f *flakyClient) UsersConsumingAPIDaily(context.Context, string, time.Time) ([]vt.UserConsumption, error) {
	return []vt.UserConsumption{{ID: "alice", Count: 10}}, nil
}
func (f *flakyClient) ServiceAccounts(context.Context, string) (map[string]bool, error) {
	return map[string]bool{}, nil
}

func TestKeepLastGoodOnFailure(t *testing.T) {
	fc := &flakyClient{}
	poller := NewPoller(fc, []string{"your_group_id_here"}, time.Minute, nil)
	poller.now = func() time.Time { return fixedNow }

	poller.PollOnce(context.Background()) // success
	snap1 := poller.Snapshot().Groups["your_group_id_here"]
	if !snap1.ScrapeSuccess || snap1.Quotas["api_requests_daily"].Used != 42 {
		t.Fatalf("first poll should succeed with data, got %+v", snap1)
	}

	poller.PollOnce(context.Background()) // failure
	snap2 := poller.Snapshot().Groups["your_group_id_here"]
	if snap2.ScrapeSuccess {
		t.Errorf("expected ScrapeSuccess=false after failure")
	}
	if snap2.Quotas["api_requests_daily"].Used != 42 {
		t.Errorf("expected last-good quota retained, got %+v", snap2.Quotas)
	}

	reg := prometheus.NewRegistry()
	reg.MustRegister(poller.ErrorsCounter())
	got := gatherMap(t, reg)
	if got[`vt_api_errors_total{endpoint=groups,group=your_group_id_here}`] != 1 {
		t.Errorf("expected 1 api error for groups endpoint, got %v", got)
	}
}
