package gitlab

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type Client struct {
	BaseURL string
	Token   string
	http    *http.Client
}

type Project struct {
	ID            int    `json:"id"`
	Name          string `json:"name"`
	Path          string `json:"path"`
	PathWithNS    string `json:"path_with_namespace"`
	HTTPURLToRepo string `json:"http_url_to_repo"`
	WebURL        string `json:"web_url"`
}

type Branch struct {
	Name string `json:"name"`
}

type MergeRequest struct {
	IID          int    `json:"iid"`
	Title        string `json:"title"`
	State        string `json:"state"`
	SourceBranch string `json:"source_branch"`
	WebURL       string `json:"web_url"`
	SHA          string `json:"sha"`
}

func New(baseURL, token string) *Client {
	return &Client{
		BaseURL: strings.TrimRight(baseURL, "/"),
		Token:   strings.TrimSpace(token),
		http:    &http.Client{Timeout: 25 * time.Second},
	}
}

func (c *Client) buildURL(endpoint string) (string, error) {
	u, err := url.Parse(strings.TrimSpace(c.BaseURL))
	if err != nil {
		return "", fmt.Errorf("invalid base url: %w", err)
	}
	rel, err := url.Parse(strings.TrimSpace(endpoint))
	if err != nil {
		return "", fmt.Errorf("invalid endpoint: %w", err)
	}
	return u.ResolveReference(rel).String(), nil
}

func (c *Client) getJSON(endpoint string, out any) error {
	link, err := c.buildURL(endpoint)
	if err != nil {
		return err
	}
	req, err := http.NewRequest(http.MethodGet, link, nil)
	if err != nil {
		return err
	}
	if c.Token != "" {
		req.Header.Set("PRIVATE-TOKEN", c.Token)
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		detail := strings.TrimSpace(string(b))
		if detail == "" {
			return fmt.Errorf("gitlab api error: %s", resp.Status)
		}
		return fmt.Errorf("gitlab api error: %s: %s", resp.Status, detail)
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

func (c *Client) postForm(endpoint string, values url.Values, out any) error {
	link, err := c.buildURL(endpoint)
	if err != nil {
		return err
	}
	body := strings.NewReader(values.Encode())
	req, err := http.NewRequest(http.MethodPost, link, body)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if c.Token != "" {
		req.Header.Set("PRIVATE-TOKEN", c.Token)
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		detail := strings.TrimSpace(string(b))
		if detail == "" {
			return fmt.Errorf("gitlab api error: %s", resp.Status)
		}
		return fmt.Errorf("gitlab api error: %s: %s", resp.Status, detail)
	}
	if out == nil {
		return nil
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

func (c *Client) ListMergeRequestsByBranch(projectID int, sourceBranch string) ([]MergeRequest, error) {
	branch := strings.TrimSpace(sourceBranch)
	if projectID <= 0 {
		return nil, fmt.Errorf("projectID 不能为空")
	}
	if branch == "" {
		return nil, fmt.Errorf("sourceBranch 不能为空")
	}
	var rows []MergeRequest
	q := url.Values{}
	q.Set("state", "opened")
	q.Set("source_branch", branch)
	q.Set("per_page", "20")
	q.Set("order_by", "updated_at")
	q.Set("sort", "desc")
	endpoint := fmt.Sprintf("/api/v4/projects/%d/merge_requests?%s", projectID, q.Encode())
	if err := c.getJSON(endpoint, &rows); err != nil {
		return nil, err
	}
	return rows, nil
}

func (c *Client) CreateMergeRequestNote(projectID, mergeRequestIID int, body string) error {
	if projectID <= 0 {
		return fmt.Errorf("projectID 不能为空")
	}
	if mergeRequestIID <= 0 {
		return fmt.Errorf("mergeRequestIID 不能为空")
	}
	text := strings.TrimSpace(body)
	if text == "" {
		return fmt.Errorf("body 不能为空")
	}
	endpoint := fmt.Sprintf("/api/v4/projects/%d/merge_requests/%d/notes", projectID, mergeRequestIID)
	form := url.Values{}
	form.Set("body", text)
	return c.postForm(endpoint, form, nil)
}

func (c *Client) SetCommitStatus(projectID int, sha, state, name, description, targetURL string) error {
	if projectID <= 0 {
		return fmt.Errorf("projectID 不能为空")
	}
	commit := strings.TrimSpace(sha)
	if commit == "" {
		return fmt.Errorf("sha 不能为空")
	}
	st := strings.ToLower(strings.TrimSpace(state))
	switch st {
	case "pending", "running", "success", "failed", "canceled":
	default:
		return fmt.Errorf("state 非法")
	}
	endpoint := fmt.Sprintf("/api/v4/projects/%d/statuses/%s", projectID, url.PathEscape(commit))
	form := url.Values{}
	form.Set("state", st)
	if strings.TrimSpace(name) != "" {
		form.Set("name", strings.TrimSpace(name))
	}
	if strings.TrimSpace(description) != "" {
		form.Set("description", strings.TrimSpace(description))
	}
	if strings.TrimSpace(targetURL) != "" {
		form.Set("target_url", strings.TrimSpace(targetURL))
	}
	return c.postForm(endpoint, form, nil)
}

func (c *Client) ListProjects() ([]Project, error) {
	var projects []Project
	endpoint := "/api/v4/projects?membership=true&simple=true&per_page=100&order_by=last_activity_at&sort=desc"
	if err := c.getJSON(endpoint, &projects); err != nil {
		return nil, err
	}
	return projects, nil
}

func (c *Client) ListBranches(projectID int) ([]Branch, error) {
	var branches []Branch
	endpoint := fmt.Sprintf("/api/v4/projects/%d/repository/branches?per_page=100", projectID)
	if err := c.getJSON(endpoint, &branches); err != nil {
		return nil, err
	}
	return branches, nil
}

func (c *Client) GetProject(projectID int) (Project, error) {
	var project Project
	endpoint := fmt.Sprintf("/api/v4/projects/%d", projectID)
	if err := c.getJSON(endpoint, &project); err != nil {
		return Project{}, err
	}
	return project, nil
}
