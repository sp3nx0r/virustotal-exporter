package vt

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestCursorFromNextLink(t *testing.T) {
	tests := []struct {
		name string
		next string
		want string
	}{
		{name: "empty", next: "", want: ""},
		{name: "with_cursor", next: "https://www.virustotal.com/api/v3/groups/g/relationships/service_accounts?limit=40&cursor=ABC123", want: "ABC123"},
		{name: "no_cursor_param", next: "https://www.virustotal.com/api/v3/groups/g/relationships/service_accounts?limit=40", want: ""},
		{name: "unparseable", next: "://bad", want: ""},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := cursorFromNextLink(test.next); got != test.want {
				t.Errorf("cursorFromNextLink(%q) = %q, want %q", test.next, got, test.want)
			}
		})
	}
}

// TestServiceAccountsPaginatesViaNextLink verifies pagination continues when the
// server signals more pages only via links.next (meta.cursor absent).
func TestServiceAccountsPaginatesViaNextLink(t *testing.T) {
	var gotCursors []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cursor := r.URL.Query().Get("cursor")
		gotCursors = append(gotCursors, cursor)
		w.Header().Set("Content-Type", "application/json")
		switch cursor {
		case "":
			// First page: no meta.cursor, continuation only via links.next.
			_, _ = w.Write([]byte(`{"data":[{"id":"sa1","type":"user"}],` +
				`"links":{"next":"` + r.URL.Path + `?limit=40&cursor=NEXT2"}}`))
		case "NEXT2":
			_, _ = w.Write([]byte(`{"data":[{"id":"sa2","type":"user"}],"meta":{},"links":{}}`))
		default:
			t.Errorf("unexpected cursor %q", cursor)
		}
	}))
	defer srv.Close()

	client := New(srv.URL, "test-key", srv.Client())
	set, err := client.ServiceAccounts(context.Background(), "your_group_id_here")
	if err != nil {
		t.Fatalf("ServiceAccounts: %v", err)
	}
	if !set["sa1"] || !set["sa2"] {
		t.Errorf("service accounts = %v, want both sa1 and sa2", set)
	}
	if len(gotCursors) != 2 || gotCursors[0] != "" || gotCursors[1] != "NEXT2" {
		t.Errorf("cursor sequence = %v, want [\"\" \"NEXT2\"]", gotCursors)
	}
}
