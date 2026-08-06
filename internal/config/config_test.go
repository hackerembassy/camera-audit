package config

import (
	"os"
	"path/filepath"
	"strings"
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
	if c.Listen != ":8080" || c.Timezone != "UTC" || c.SnapshotLease.Value().Seconds() != 75 || c.Telegram.BatchWindow.Value().Minutes() != 5 || c.Database == "${TEST_DB}" {
		t.Fatalf("defaults or expansion missing: %#v", c)
	}
}

func TestLoadAcceptsIANAAndRejectsInvalidTimezone(t *testing.T) {
	for _, tt := range []struct {
		name     string
		timezone string
		wantErr  bool
	}{
		{name: "IANA", timezone: "Asia/Yerevan"},
		{name: "invalid", timezone: "Asia/Yerevn", wantErr: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			p := filepath.Join(t.TempDir(), "config.yaml")
			data := []byte("frigate_url: https://frigate:8971\ngo2rtc_url: http://frigate:1984\ndatabase: audit.db\ntrusted_proxies: [127.0.0.0/8]\ntimezone: " + tt.timezone + "\n")
			if err := os.WriteFile(p, data, 0o600); err != nil {
				t.Fatal(err)
			}
			cfg, err := Load(p)
			if (err != nil) != tt.wantErr {
				t.Fatalf("Load() error=%v, wantErr=%v", err, tt.wantErr)
			}
			if err == nil {
				location, err := cfg.Location()
				if err != nil || location.String() != tt.timezone {
					t.Fatalf("location=%v err=%v", location, err)
				}
			}
		})
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

func TestLoadRejectsNonPositiveDurations(t *testing.T) {
	for _, field := range []string{"poll_interval", "activity_window", "snapshot_lease", "privacy_clear_delay", "retention"} {
		t.Run(field, func(t *testing.T) {
			p := filepath.Join(t.TempDir(), "config.yaml")
			data := []byte("frigate_url: https://frigate:8971\ngo2rtc_url: http://frigate:1984\ndatabase: audit.db\ntrusted_proxies: [127.0.0.0/8]\n" + field + ": 0s\n")
			if err := os.WriteFile(p, data, 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := Load(p); err == nil || !strings.Contains(err.Error(), field) {
				t.Fatalf("Load() error=%v, want error for %s", err, field)
			}
		})
	}
}

func TestLoadRejectsInvalidUpstreamURLs(t *testing.T) {
	for _, tt := range []struct {
		name, frigateURL, go2rtcURL string
	}{
		{name: "relative Frigate URL", frigateURL: "frigate:8971", go2rtcURL: "http://frigate:1984"},
		{name: "unsupported go2rtc scheme", frigateURL: "https://frigate:8971", go2rtcURL: "ftp://frigate/streams"},
		{name: "embedded credentials", frigateURL: "https://admin:secret@frigate:8971", go2rtcURL: "http://frigate:1984"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			p := filepath.Join(t.TempDir(), "config.yaml")
			data := []byte("frigate_url: " + tt.frigateURL + "\ngo2rtc_url: " + tt.go2rtcURL + "\ndatabase: audit.db\ntrusted_proxies: [127.0.0.0/8]\n")
			if err := os.WriteFile(p, data, 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := Load(p); err == nil {
				t.Fatal("expected invalid upstream URL to be rejected")
			}
		})
	}
}

func TestLoadRejectsIncompleteEnabledMQTT(t *testing.T) {
	p := filepath.Join(t.TempDir(), "config.yaml")
	data := []byte("frigate_url: https://frigate:8971\ngo2rtc_url: http://frigate:1984\ndatabase: audit.db\ntrusted_proxies: [127.0.0.0/8]\nmqtt:\n  enabled: true\n")
	if err := os.WriteFile(p, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(p); err == nil {
		t.Fatal("expected incomplete enabled MQTT configuration to be rejected")
	}
}

func TestLoadValidatesEnabledTelegram(t *testing.T) {
	for _, telegram := range []string{
		"telegram:\n  enabled: true\n",
		"telegram:\n  enabled: true\n  bot_token: token\n  chat_id: chat\n  batch_window: 0s\n",
	} {
		p := filepath.Join(t.TempDir(), "config.yaml")
		data := []byte("frigate_url: https://frigate:8971\ngo2rtc_url: http://frigate:1984\ndatabase: audit.db\ntrusted_proxies: [127.0.0.0/8]\n" + telegram)
		if err := os.WriteFile(p, data, 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := Load(p); err == nil || !strings.Contains(err.Error(), "Telegram") && !strings.Contains(err.Error(), "telegram") {
			t.Fatalf("Load() error=%v, want Telegram validation error", err)
		}
	}
}

func TestLoadRejectsUnknownFields(t *testing.T) {
	p := filepath.Join(t.TempDir(), "config.yaml")
	data := []byte("frigate_url: https://frigate:8971\ngo2rtc_url: http://frigate:1984\ndatabase: audit.db\ntrusted_proxies: [127.0.0.0/8]\npoll_intervall: 2s\n")
	if err := os.WriteFile(p, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(p); err == nil || !strings.Contains(err.Error(), "poll_intervall") {
		t.Fatalf("Load() error=%v, want unknown-field error", err)
	}
}
