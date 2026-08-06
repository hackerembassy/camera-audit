package go2rtc

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestCredentialRedaction(t *testing.T) {
	in := `digraph { a [label="rtsp://user:secret@camera.local/live"] }`
	got := credentialURL.ReplaceAllString(in, `${1}***@`)
	want := `digraph { a [label="rtsp://***@camera.local/live"] }`
	if got != want {
		t.Fatalf("got %q", got)
	}
}

func TestEndpoints(t *testing.T) {
	tests := []struct {
		base, streams, dot string
	}{
		{"http://frigate:1984", "http://frigate:1984/api/streams", "http://frigate:1984/api/streams.dot"},
		{"http://frigate:1984/api", "http://frigate:1984/api/streams", "http://frigate:1984/api/streams.dot"},
		{"http://frigate:5000/api/go2rtc", "http://frigate:5000/api/go2rtc/streams", "http://frigate:5000/api/go2rtc/streams.dot"},
	}
	for _, tt := range tests {
		streams, dot := endpoints(tt.base)
		if streams != tt.streams || dot != tt.dot {
			t.Errorf("endpoints(%q)=(%q,%q), want (%q,%q)", tt.base, streams, dot, tt.streams, tt.dot)
		}
	}
}

func TestBasicAuthIsSentToBothEndpoints(t *testing.T) {
	seen := map[string]bool{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		username, password, ok := r.BasicAuth()
		if !ok || username != "audit" || password != "secret" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		seen[r.URL.Path] = true
		switch r.URL.Path {
		case "/api/streams":
			_, _ = w.Write([]byte(`{}`))
		case "/api/streams.dot":
			_, _ = w.Write([]byte(`digraph {}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	client := New(server.URL, "audit", "secret")
	if _, err := client.Streams(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := client.SanitizedDOT(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !seen["/api/streams"] || !seen["/api/streams.dot"] {
		t.Fatalf("authenticated requests not seen on both endpoints: %#v", seen)
	}
}
