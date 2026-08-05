package vt

// Quota mirrors a single entry of a group's `quotas` attribute.
type Quota struct {
	Allowed float64 `json:"allowed"`
	Used    float64 `json:"used"`
}

// Group is the response of GET /groups/{id}.
type Group struct {
	Data struct {
		ID         string `json:"id"`
		Attributes struct {
			Quotas map[string]Quota `json:"quotas"`
		} `json:"attributes"`
	} `json:"data"`
}

// APIUsage is the response of GET /groups/{id}/api_usage. When queried for a
// single day (start_date == end_date), the Total maps hold that day's counts.
type APIUsage struct {
	Total             map[string]float64 `json:"total"`
	TotalNonConsuming map[string]float64 `json:"total_endpoints_not_consuming_quota"`
}

// usersConsumingQuota is the response of
// GET /groups/{id}/users_consuming_quota/{quota_name}.
type usersConsumingQuota struct {
	Data []struct {
		ID         string `json:"id"`
		Type       string `json:"type"`
		Attributes struct {
			Quotas map[string]Quota `json:"quotas"`
		} `json:"attributes"`
		ContextAttributes struct {
			QuotaConsumed float64 `json:"quota_consumed_from_group"`
		} `json:"context_attributes"`
	} `json:"data"`
	Meta struct {
		Cursor string `json:"cursor"`
	} `json:"meta"`
	Links struct {
		Next string `json:"next"`
	} `json:"links"`
}

// UserConsumption is a flattened per-user consumption record. Quotas holds the
// user's own quota limits (allowed/used) when available.
type UserConsumption struct {
	ID     string
	Count  float64
	Quotas map[string]Quota
}

// relationship is the generic response shape for relationship endpoints such as
// GET /groups/{id}/relationships/service_accounts.
type relationship struct {
	Data []struct {
		ID   string `json:"id"`
		Type string `json:"type"`
	} `json:"data"`
	Meta struct {
		Cursor string `json:"cursor"`
	} `json:"meta"`
	Links struct {
		Next string `json:"next"`
	} `json:"links"`
}

// apiError is the VirusTotal error envelope.
type apiError struct {
	Error struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}
