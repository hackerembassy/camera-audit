package config

import (
	"bytes"
	"fmt"
	"net/netip"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"
	_ "time/tzdata"

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
	Listen                       string   `yaml:"listen"`
	FrigateURL                   string   `yaml:"frigate_url"`
	FrigateTLSCAFile             string   `yaml:"frigate_tls_ca_file"`
	FrigateTLSServerName         string   `yaml:"frigate_tls_server_name"`
	FrigateTLSInsecureSkipVerify bool     `yaml:"frigate_tls_insecure_skip_verify"`
	FrigateProxySecret           string   `yaml:"frigate_proxy_secret"`
	Go2RTCURL                    string   `yaml:"go2rtc_url"`
	Go2RTCUsername               string   `yaml:"go2rtc_username"`
	Go2RTCPassword               string   `yaml:"go2rtc_password"`
	Database                     string   `yaml:"database"`
	Timezone                     string   `yaml:"timezone"`
	IdentityHeader               string   `yaml:"identity_header"`
	TrustedProxies               []string `yaml:"trusted_proxies"`
	PollInterval                 Duration `yaml:"poll_interval"`
	ActivityWindow               Duration `yaml:"activity_window"`
	SnapshotLease                Duration `yaml:"snapshot_lease"`
	PrivacyClearDelay            Duration `yaml:"privacy_clear_delay"`
	Retention                    Duration `yaml:"retention"`
	BirdseyeCameras              []string `yaml:"birdseye_cameras"`
	Rules                        []Rule   `yaml:"rules"`
	MQTT                         MQTT     `yaml:"mqtt"`
}

func Load(path string) (Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return Config{}, err
	}
	b = []byte(os.ExpandEnv(string(b)))
	c := Config{
		Listen:            ":8080",
		Timezone:          "UTC",
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
	decoder := yaml.NewDecoder(bytes.NewReader(b))
	decoder.KnownFields(true)
	if err := decoder.Decode(&c); err != nil {
		return Config{}, err
	}
	if c.FrigateURL == "" || c.Go2RTCURL == "" || c.Database == "" {
		return Config{}, fmt.Errorf("frigate_url, go2rtc_url, and database are required")
	}
	if err := validateHTTPURL("frigate_url", c.FrigateURL); err != nil {
		return Config{}, err
	}
	if err := validateHTTPURL("go2rtc_url", c.Go2RTCURL); err != nil {
		return Config{}, err
	}
	if (c.Go2RTCUsername == "") != (c.Go2RTCPassword == "") {
		return Config{}, fmt.Errorf("go2rtc_username and go2rtc_password must either both be set or both be empty")
	}
	if c.FrigateTLSCAFile != "" && c.FrigateTLSInsecureSkipVerify {
		return Config{}, fmt.Errorf("frigate_tls_ca_file and frigate_tls_insecure_skip_verify cannot be used together")
	}
	if len(c.TrustedProxies) == 0 {
		return Config{}, fmt.Errorf("trusted_proxies must contain the Authentik proxy network")
	}
	for name, duration := range map[string]Duration{
		"poll_interval":       c.PollInterval,
		"activity_window":     c.ActivityWindow,
		"snapshot_lease":      c.SnapshotLease,
		"privacy_clear_delay": c.PrivacyClearDelay,
		"retention":           c.Retention,
	} {
		if duration.Value() <= 0 {
			return Config{}, fmt.Errorf("%s must be greater than zero", name)
		}
	}
	if _, err := c.Location(); err != nil {
		return Config{}, err
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
	if c.IdentityHeader == "" {
		return Config{}, fmt.Errorf("identity_header must not be empty")
	}
	if c.MQTT.Enabled {
		if strings.TrimSpace(c.MQTT.Broker) == "" || strings.TrimSpace(c.MQTT.ClientID) == "" ||
			strings.TrimSpace(c.MQTT.TopicPrefix) == "" || strings.TrimSpace(c.MQTT.DiscoveryPrefix) == "" {
			return Config{}, fmt.Errorf("enabled MQTT requires broker, client_id, topic_prefix, and discovery_prefix")
		}
	}
	return c, nil
}

func validateHTTPURL(name, raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
		return fmt.Errorf("%s must be an absolute HTTP or HTTPS URL", name)
	}
	if u.User != nil {
		return fmt.Errorf("%s must not contain credentials", name)
	}
	if u.RawQuery != "" || u.Fragment != "" {
		return fmt.Errorf("%s must not contain a query or fragment", name)
	}
	return nil
}

func (c Config) Location() (*time.Location, error) {
	name := strings.TrimSpace(c.Timezone)
	if name == "" {
		name = "UTC"
	}
	location, err := time.LoadLocation(name)
	if err != nil {
		return nil, fmt.Errorf("timezone %q: %w", name, err)
	}
	return location, nil
}
