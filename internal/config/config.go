package config

import (
	"fmt"
	"net/netip"
	"os"
	"regexp"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

type Duration time.Duration

func (d *Duration) UnmarshalYAML(node *yaml.Node) error {
	v, err := time.ParseDuration(node.Value)
	if err != nil {
		return err
	}
	*d = Duration(v)
	return nil
}

func (d Duration) Value() time.Duration { return time.Duration(d) }

type Rule struct {
	Name       string `yaml:"name"`
	Stream     string `yaml:"stream"`
	RemoteCIDR string `yaml:"remote_cidr"`
	Protocol   string `yaml:"protocol"`
	UserAgent  string `yaml:"user_agent"`
	Actor      string `yaml:"actor"`
	ActorType  string `yaml:"actor_type"`
	Suppressed bool   `yaml:"suppressed"`
}

type MQTT struct {
	Enabled         bool   `yaml:"enabled"`
	Broker          string `yaml:"broker"`
	ClientID        string `yaml:"client_id"`
	Username        string `yaml:"username"`
	Password        string `yaml:"password"`
	TopicPrefix     string `yaml:"topic_prefix"`
	DiscoveryPrefix string `yaml:"discovery_prefix"`
}

type Config struct {
	Listen            string   `yaml:"listen"`
	FrigateURL        string   `yaml:"frigate_url"`
	Go2RTCURL         string   `yaml:"go2rtc_url"`
	Go2RTCUsername    string   `yaml:"go2rtc_username"`
	Go2RTCPassword    string   `yaml:"go2rtc_password"`
	Database          string   `yaml:"database"`
	IdentityHeader    string   `yaml:"identity_header"`
	TrustedProxies    []string `yaml:"trusted_proxies"`
	PollInterval      Duration `yaml:"poll_interval"`
	ActivityWindow    Duration `yaml:"activity_window"`
	SnapshotLease     Duration `yaml:"snapshot_lease"`
	PrivacyClearDelay Duration `yaml:"privacy_clear_delay"`
	Retention         Duration `yaml:"retention"`
	BirdseyeCameras   []string `yaml:"birdseye_cameras"`
	Rules             []Rule   `yaml:"rules"`
	MQTT              MQTT     `yaml:"mqtt"`
}

func Load(path string) (Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return Config{}, err
	}
	b = []byte(os.ExpandEnv(string(b)))
	c := Config{
		Listen:            ":8080",
		IdentityHeader:    "X-authentik-username",
		PollInterval:      Duration(2 * time.Second),
		ActivityWindow:    Duration(5 * time.Minute),
		SnapshotLease:     Duration(75 * time.Second),
		PrivacyClearDelay: Duration(30 * time.Second),
		Retention:         Duration(365 * 24 * time.Hour),
		MQTT: MQTT{
			ClientID:        "camera-audit",
			TopicPrefix:     "camera_audit",
			DiscoveryPrefix: "homeassistant",
		},
	}
	if err := yaml.Unmarshal(b, &c); err != nil {
		return Config{}, err
	}
	if c.FrigateURL == "" || c.Go2RTCURL == "" || c.Database == "" {
		return Config{}, fmt.Errorf("frigate_url, go2rtc_url, and database are required")
	}
	if (c.Go2RTCUsername == "") != (c.Go2RTCPassword == "") {
		return Config{}, fmt.Errorf("go2rtc_username and go2rtc_password must either both be set or both be empty")
	}
	if len(c.TrustedProxies) == 0 {
		return Config{}, fmt.Errorf("trusted_proxies must contain the Authentik proxy network")
	}
	for _, raw := range c.TrustedProxies {
		if _, err := netip.ParsePrefix(raw); err != nil {
			return Config{}, fmt.Errorf("trusted proxy %q: %w", raw, err)
		}
	}
	for i, r := range c.Rules {
		if r.Name == "" || r.Actor == "" {
			return Config{}, fmt.Errorf("rule %d requires name and actor", i)
		}
		if r.RemoteCIDR != "" {
			if _, err := netip.ParsePrefix(r.RemoteCIDR); err != nil {
				return Config{}, fmt.Errorf("rule %q remote_cidr: %w", r.Name, err)
			}
		}
		if r.UserAgent != "" {
			if _, err := regexp.Compile(r.UserAgent); err != nil {
				return Config{}, fmt.Errorf("rule %q user_agent: %w", r.Name, err)
			}
		}
	}
	c.IdentityHeader = strings.TrimSpace(c.IdentityHeader)
	return c, nil
}
