package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadDefaultsAndEnvironment(t *testing.T) {
	t.Setenv("TEST_DB", filepath.Join(t.TempDir(), "audit.db"))
	p := filepath.Join(t.TempDir(), "config.yaml")
	data := []byte("frigate_url: https://frigate:8971\ngo2rtc_url: http://frigate:1984\ndatabase: ${TEST_DB}\ntrusted_proxies: [127.0.0.0/8]\n")
	if err := os.WriteFile(p, data, 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if c.Listen != ":8080" || c.SnapshotLease.Value().Seconds() != 75 || c.Database == "${TEST_DB}" {
		t.Fatalf("defaults or expansion missing: %#v", c)
	}
}

func TestLoadRejectsPartialGo2RTCAuthentication(t *testing.T) {
	p := filepath.Join(t.TempDir(), "config.yaml")
	data := []byte("frigate_url: https://frigate:8971\ngo2rtc_url: http://frigate:1984\ngo2rtc_username: audit\ndatabase: audit.db\ntrusted_proxies: [127.0.0.0/8]\n")
	if err := os.WriteFile(p, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(p); err == nil {
		t.Fatal("expected partial go2rtc credentials to be rejected")
	}
}

func TestLoadRejectsConflictingFrigateTLSOptions(t *testing.T) {
	p := filepath.Join(t.TempDir(), "config.yaml")
	data := []byte("frigate_url: https://frigate:8971\nfrigate_tls_ca_file: ca.pem\nfrigate_tls_insecure_skip_verify: true\ngo2rtc_url: http://frigate:1984\ndatabase: audit.db\ntrusted_proxies: [127.0.0.0/8]\n")
	if err := os.WriteFile(p, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(p); err == nil {
		t.Fatal("expected conflicting Frigate TLS settings to be rejected")
	}
}
