package go2rtc

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"

	"xkem.am/camera-audit/internal/model"
)

type Client struct {
	streamsURL string
	dotURL     string
	username   string
	password   string
	http       *http.Client
}

func New(base, username, password string) *Client {
	streamsURL, dotURL := endpoints(base)
	return &Client{
		streamsURL: streamsURL,
		dotURL:     dotURL,
		username:   username,
		password:   password,
		http:       &http.Client{Timeout: 5 * time.Second},
	}
}

func endpoints(base string) (streamsURL, dotURL string) {
	base = strings.TrimRight(base, "/")
	switch {
	case strings.HasSuffix(base, "/api/go2rtc"):
		// Frigate exposes a narrow, sanitized JSON proxy. It does not expose the
		// go2rtc DOT graph, so dotURL will predictably be unavailable in this mode.
		return base + "/streams", base + "/streams.dot"
	case strings.HasSuffix(base, "/api"):
		return base + "/streams", base + "/streams.dot"
	default:
		return base + "/api/streams", base + "/api/streams.dot"
	}
}

func (c *Client) Streams(ctx context.Context) (map[string]model.Stream, error) {
	var out map[string]model.Stream
	if err := c.getJSON(ctx, c.streamsURL, &out); err != nil {
		return nil, err
	}
	return out, nil
}

var credentialURL = regexp.MustCompile(`(?i)([a-z][a-z0-9+.-]*://)[^/@\s"]+@`)

func (c *Client) SanitizedDOT(ctx context.Context) (string, error) {
	req, err := c.newRequest(ctx, c.dotURL)
	if err != nil {
		return "", err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("go2rtc DOT returned %s", resp.Status)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return "", err
	}
	return credentialURL.ReplaceAllString(string(b), `${1}***@`), nil
}

func (c *Client) getJSON(ctx context.Context, url string, dst any) error {
	req, err := c.newRequest(ctx, url)
	if err != nil {
		return err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("go2rtc streams returned %s", resp.Status)
	}
	return json.NewDecoder(io.LimitReader(resp.Body, 16<<20)).Decode(dst)
}

func (c *Client) newRequest(ctx context.Context, url string) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	if c.username != "" {
		req.SetBasicAuth(c.username, c.password)
	}
	return req, nil
}
