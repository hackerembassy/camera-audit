package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadDefaultsAndEnvironment(t *testing.T) {
	t.Setenv("TEST_DB", filepath.Join(t.TempDir(), "audit.db"))
	p := filepath.Join(t.TempDir(), "config.yaml")
	data := []byte("frigate_url: http://frigate:8971\ngo2rtc_url: http://frigate:5000/api/go2rtc\ndatabase: ${TEST_DB}\ntrusted_proxies: [127.0.0.0/8]\n")
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
