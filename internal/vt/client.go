// Package vt is a minimal client for the VirusTotal v3 API endpoints needed to
// report group API-usage and quota information.
package vt

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// DefaultBaseURL is the public VirusTotal v3 API root.
const DefaultBaseURL = "https://www.virustotal.com/api/v3"

// maxUsersPerPage is the documented maximum page size for the
// users_consuming_quota endpoint.
const maxUsersPerPage = 40

// Client talks to the VirusTotal v3 API using a group-admin API key.
type Client struct {
	baseURL string
	apiKey  string
	hc      *http.Client
}

// New returns a Client. If hc is nil a default client with a 30s timeout is
// used. A trailing slash on baseURL is trimmed.
func New(baseURL, apiKey string, hc *http.Client) *Client {
	if baseURL == "" {
		baseURL = DefaultBaseURL
	}
	if hc == nil {
		hc = &http.Client{Timeout: 30 * time.Second}
	}
	return &Client{
		baseURL: strings.TrimRight(baseURL, "/"),
		apiKey:  apiKey,
		hc:      hc,
	}
}

// APIError is returned for non-2xx responses from the API.
type APIError struct {
	Status  int
	Code    string
	Message string
}

func (e *APIError) Error() string {
	if e.Code != "" {
		return fmt.Sprintf("virustotal API error: status=%d code=%s message=%s", e.Status, e.Code, e.Message)
	}
	return fmt.Sprintf("virustotal API error: status=%d", e.Status)
}

// get performs an authenticated GET and decodes the JSON body into out.
func (c *Client) get(ctx context.Context, path string, query url.Values, out any) error {
	u := c.baseURL + path
	if len(query) > 0 {
		u += "?" + query.Encode()
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return err
	}
	req.Header.Set("x-apikey", c.apiKey)
	req.Header.Set("accept", "application/json")

	resp, err := c.hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		apiErr := &APIError{Status: resp.StatusCode}
		var e apiError
		if json.Unmarshal(body, &e) == nil {
			apiErr.Code = e.Error.Code
			apiErr.Message = e.Error.Message
		}
		return apiErr
	}
	if out == nil {
		return nil
	}
	if err := json.Unmarshal(body, out); err != nil {
		return fmt.Errorf("decoding response from %q: %w", path, err)
	}
	return nil
}

// cursorFromNextLink extracts the "cursor" query parameter from a VirusTotal
// pagination "links.next" URL, returning "" if absent or unparseable. It is used
// as a fallback when the response does not populate meta.cursor.
func cursorFromNextLink(next string) string {
	if next == "" {
		return ""
	}
	u, err := url.Parse(next)
	if err != nil {
		return ""
	}
	return u.Query().Get("cursor")
}

// GroupQuotas returns the group's quota map (api_requests_hourly/daily/monthly, etc.).
func (c *Client) GroupQuotas(ctx context.Context, groupID string) (map[string]Quota, error) {
	var g Group
	if err := c.get(ctx, "/groups/"+url.PathEscape(groupID), nil, &g); err != nil {
		return nil, err
	}
	return g.Data.Attributes.Quotas, nil
}

// APIUsage returns the group's per-endpoint usage for the given UTC day.
func (c *Client) APIUsage(ctx context.Context, groupID string, day time.Time) (*APIUsage, error) {
	d := day.UTC().Format("20060102")
	q := url.Values{"start_date": {d}, "end_date": {d}}
	var u APIUsage
	if err := c.get(ctx, "/groups/"+url.PathEscape(groupID)+"/api_usage", q, &u); err != nil {
		return nil, err
	}
	return &u, nil
}

// UsersConsumingAPIDaily returns per-user API request counts for the given UTC
// day, following cursor pagination to completion.
func (c *Client) UsersConsumingAPIDaily(ctx context.Context, groupID string, day time.Time) ([]UserConsumption, error) {
	period := day.UTC().Format("2006-01-02")
	path := "/groups/" + url.PathEscape(groupID) + "/users_consuming_quota/api_requests_daily"

	var out []UserConsumption
	cursor := ""
	for {
		q := url.Values{
			"period":     {period},
			"limit":      {strconv.Itoa(maxUsersPerPage)},
			"attributes": {"quotas"},
		}
		if cursor != "" {
			q.Set("cursor", cursor)
		}
		var page usersConsumingQuota
		if err := c.get(ctx, path, q, &page); err != nil {
			return nil, err
		}
		for _, d := range page.Data {
			out = append(out, UserConsumption{
				ID:     d.ID,
				Count:  d.ContextAttributes.QuotaConsumed,
				Quotas: d.Attributes.Quotas,
			})
		}
		next := page.Meta.Cursor
		if next == "" {
			next = cursorFromNextLink(page.Links.Next)
		}
		if next == "" {
			break
		}
		cursor = next
	}
	return out, nil
}

// ServiceAccounts returns the set of usernames that are service accounts for the
// group, following cursor pagination to completion.
func (c *Client) ServiceAccounts(ctx context.Context, groupID string) (map[string]bool, error) {
	path := "/groups/" + url.PathEscape(groupID) + "/relationships/service_accounts"
	set := make(map[string]bool)
	cursor := ""
	for {
		q := url.Values{"limit": {strconv.Itoa(maxUsersPerPage)}}
		if cursor != "" {
			q.Set("cursor", cursor)
		}
		var page relationship
		if err := c.get(ctx, path, q, &page); err != nil {
			return nil, err
		}
		for _, d := range page.Data {
			set[d.ID] = true
		}
		next := page.Meta.Cursor
		if next == "" {
			next = cursorFromNextLink(page.Links.Next)
		}
		if next == "" {
			break
		}
		cursor = next
	}
	return set, nil
}
