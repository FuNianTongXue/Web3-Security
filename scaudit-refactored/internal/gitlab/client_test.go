package gitlab

import (
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func mockJSONResponse(status int, body string) *http.Response {
	return &http.Response{
		StatusCode: status,
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       io.NopCloser(strings.NewReader(body)),
	}
}

func TestListProjectsKeepsQuery(t *testing.T) {
	c := New("https://gitlab.example.com", "tok-1")
	c.http = &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if r.URL.Path != "/api/v4/projects" {
			t.Fatalf("path mismatch: %s", r.URL.Path)
		}
		q := r.URL.Query()
		if q.Get("membership") != "true" || q.Get("simple") != "true" {
			t.Fatalf("query mismatch: %s", r.URL.RawQuery)
		}
		if r.Header.Get("PRIVATE-TOKEN") != "tok-1" {
			t.Fatalf("token header missing")
		}
		return mockJSONResponse(http.StatusOK, `[{"id":1,"name":"demo","path":"demo","path_with_namespace":"sec/demo","http_url_to_repo":"https://x/demo.git","web_url":"https://x/demo"}]`), nil
	})}

	rows, err := c.ListProjects()
	if err != nil {
		t.Fatalf("ListProjects failed: %v", err)
	}
	if len(rows) != 1 || rows[0].ID != 1 {
		t.Fatalf("unexpected projects: %+v", rows)
	}
}

func TestListMergeRequestsByBranch(t *testing.T) {
	c := New("https://gitlab.example.com", "tok-2")
	c.http = &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if r.URL.Path != "/api/v4/projects/7/merge_requests" {
			t.Fatalf("path mismatch: %s", r.URL.Path)
		}
		q := r.URL.Query()
		if q.Get("state") != "opened" || q.Get("source_branch") != "feature/security-gate" {
			t.Fatalf("query mismatch: %s", r.URL.RawQuery)
		}
		return mockJSONResponse(http.StatusOK, `[{"iid":12,"title":"mr demo","state":"opened","source_branch":"feature/security-gate","web_url":"https://gitlab/mr/12","sha":"abc123"}]`), nil
	})}

	rows, err := c.ListMergeRequestsByBranch(7, "feature/security-gate")
	if err != nil {
		t.Fatalf("ListMergeRequestsByBranch failed: %v", err)
	}
	if len(rows) != 1 || rows[0].IID != 12 {
		t.Fatalf("unexpected merge requests: %+v", rows)
	}
}

func TestCreateNoteAndSetCommitStatus(t *testing.T) {
	hitNote := false
	hitStatus := false
	c := New("https://gitlab.example.com", "tok-3")
	c.http = &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		switch {
		case r.URL.Path == "/api/v4/projects/3/merge_requests/9/notes":
			if r.Method != http.MethodPost {
				t.Fatalf("note method mismatch: %s", r.Method)
			}
			if err := r.ParseForm(); err != nil {
				t.Fatalf("parse note form failed: %v", err)
			}
			if strings.TrimSpace(r.FormValue("body")) == "" {
				t.Fatalf("note body should not be empty")
			}
			hitNote = true
			return mockJSONResponse(http.StatusCreated, `{"id":1}`), nil
		case strings.HasPrefix(r.URL.Path, "/api/v4/projects/3/statuses/"):
			if r.Method != http.MethodPost {
				t.Fatalf("status method mismatch: %s", r.Method)
			}
			expectEscaped := url.PathEscape("abc/123")
			if !strings.Contains(r.URL.EscapedPath(), expectEscaped) {
				t.Fatalf("sha escaped path mismatch: got=%s expectPart=%s", r.URL.EscapedPath(), expectEscaped)
			}
			if err := r.ParseForm(); err != nil {
				t.Fatalf("parse status form failed: %v", err)
			}
			if r.FormValue("state") != "failed" || r.FormValue("name") != "scaudit/ci-gate" {
				t.Fatalf("status form mismatch: %+v", r.Form)
			}
			hitStatus = true
			return mockJSONResponse(http.StatusCreated, `{"id":2}`), nil
		default:
			t.Fatalf("unexpected path: %s", r.URL.Path)
			return nil, nil
		}
	})}

	if err := c.CreateMergeRequestNote(3, 9, "gate blocked"); err != nil {
		t.Fatalf("CreateMergeRequestNote failed: %v", err)
	}
	if err := c.SetCommitStatus(3, "abc/123", "failed", "scaudit/ci-gate", "blocked", "https://ci/job/1"); err != nil {
		t.Fatalf("SetCommitStatus failed: %v", err)
	}
	if !hitNote || !hitStatus {
		t.Fatalf("expected both note/status endpoints to be hit")
	}
}
