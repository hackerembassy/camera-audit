package mqttpub

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"log/slog"
	"regexp"
	"strings"
	"sync"
	"time"

	mqtt "github.com/eclipse/paho.mqtt.golang"

	"xkem.am/camera-audit/internal/config"
)

type Publisher struct {
	cfg       config.MQTT
	client    mqtt.Client
	log       *slog.Logger
	mu        sync.Mutex
	states    map[string]bool
	available bool
}

func New(cfg config.MQTT, log *slog.Logger) (*Publisher, error) {
	p := &Publisher{cfg: cfg, log: log, states: make(map[string]bool)}
	if !cfg.Enabled {
		return p, nil
	}
	opts := mqtt.NewClientOptions().AddBroker(cfg.Broker).SetClientID(cfg.ClientID).
		SetUsername(cfg.Username).SetPassword(cfg.Password).SetAutoReconnect(true).
		SetConnectRetry(true).SetConnectRetryInterval(5 * time.Second).
		SetOrderMatters(false)
	opts.SetWill(cfg.TopicPrefix+"/availability", "offline", 1, true)
	opts.OnConnect = func(c mqtt.Client) {
		p.subscribeRetainedStateCleanup(c)
		// The callback can race with Manager.Set. Snapshot under the lock, then
		// publish without holding it because broker I/O may block.
		p.mu.Lock()
		available := p.available
		states := make(map[string]bool, len(p.states))
		for camera, active := range p.states {
			states[camera] = active
		}
		p.mu.Unlock()
		p.publish(c, cfg.TopicPrefix+"/availability", availability(available), true)
		for camera, active := range states {
			p.publishDiscovery(c, camera)
			p.publish(c, p.stateTopic(camera), state(active), true)
		}
	}
	opts.OnConnectionLost = func(_ mqtt.Client, err error) { log.Warn("MQTT connection lost", "error", err) }
	p.client = mqtt.NewClient(opts)
	token := p.client.Connect()
	if !token.WaitTimeout(15 * time.Second) {
		// ConnectRetry keeps working in the background. Auditing and proxying do
		// not need to be unavailable merely because the notification path is down.
		log.Warn("initial MQTT connection timed out; retrying in background")
		return p, nil
	}
	if token.Error() != nil {
		return nil, token.Error()
	}
	return p, nil
}

func (p *Publisher) Set(camera string, active bool) {
	if !p.cfg.Enabled {
		return
	}
	p.mu.Lock()
	p.states[camera] = active
	p.mu.Unlock()
	if !p.client.IsConnected() {
		return
	}
	p.publishDiscovery(p.client, camera)
	p.publish(p.client, p.stateTopic(camera), state(active), true)
}

func (p *Publisher) SetAvailable(available bool) {
	if !p.cfg.Enabled {
		return
	}
	p.mu.Lock()
	p.available = available
	p.mu.Unlock()
	if p.client.IsConnected() {
		p.publish(p.client, p.cfg.TopicPrefix+"/availability", availability(available), true)
	}
}

func (p *Publisher) Close() {
	if p.client != nil {
		p.mu.Lock()
		cameras := make([]string, 0, len(p.states))
		for camera := range p.states {
			cameras = append(cameras, camera)
			p.states[camera] = false
		}
		p.available = false
		p.mu.Unlock()
		if p.client.IsConnected() {
			for _, camera := range cameras {
				p.publish(p.client, p.stateTopic(camera), state(false), true)
			}
		}
		p.publish(p.client, p.cfg.TopicPrefix+"/availability", "offline", true)
		p.client.Disconnect(250)
	}
}

func (p *Publisher) subscribeRetainedStateCleanup(c mqtt.Client) {
	filter := p.cfg.TopicPrefix + "/+/viewer"
	token := c.Subscribe(filter, 1, func(client mqtt.Client, message mqtt.Message) {
		if !p.shouldClearRetained(message.Topic(), string(message.Payload()), message.Retained()) {
			return
		}
		p.log.Info("clear stale retained MQTT viewer state", "topic", message.Topic())
		p.publish(client, message.Topic(), state(false), true)
	})
	if !token.WaitTimeout(5 * time.Second) {
		p.log.Warn("subscribe MQTT retained-state cleanup timed out", "topic", filter)
		return
	}
	if token.Error() != nil {
		p.log.Warn("subscribe MQTT retained-state cleanup", "topic", filter, "error", token.Error())
	}
}

func (p *Publisher) shouldClearRetained(topic, payload string, retained bool) bool {
	if !retained || strings.TrimSpace(payload) != state(true) {
		return false
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	for camera, active := range p.states {
		if p.stateTopic(camera) == topic {
			if active {
				return false
			}
		}
	}
	return true
}

var nonSlug = regexp.MustCompile(`[^a-z0-9]+`)

func slug(s string) string {
	s = strings.ToLower(s)
	return strings.Trim(nonSlug.ReplaceAllString(s, "_"), "_")
}

func cameraID(camera string) string {
	base := slug(camera)
	if base == "" {
		base = "camera"
	}
	digest := sha256.Sum256([]byte(camera))
	return fmt.Sprintf("%s_%x", base, digest[:4])
}

func state(active bool) string {
	if active {
		return "ON"
	}
	return "OFF"
}

func availability(available bool) string {
	if available {
		return "online"
	}
	return "offline"
}

func (p *Publisher) stateTopic(camera string) string {
	return p.cfg.TopicPrefix + "/" + cameraID(camera) + "/viewer"
}

func (p *Publisher) publishDiscovery(c mqtt.Client, camera string) {
	objectID := cameraID(camera)
	id := p.cfg.ClientID + "_" + objectID + "_viewer"
	payload, _ := json.Marshal(map[string]any{
		"name": camera + " external viewer active", "unique_id": id,
		"state_topic": p.stateTopic(camera), "availability_topic": p.cfg.TopicPrefix + "/availability",
		"payload_on": "ON", "payload_off": "OFF", "device_class": "occupancy",
		"device": map[string]any{"identifiers": []string{p.cfg.ClientID}, "name": "Camera access audit"},
	})
	// Remove discovery retained by versions that used the collision-prone plain
	// slug. An empty retained payload is MQTT Discovery's deletion mechanism.
	legacyTopic := fmt.Sprintf("%s/binary_sensor/%s/%s/config", p.cfg.DiscoveryPrefix, p.cfg.ClientID, slug(camera))
	p.publish(c, legacyTopic, "", true)
	topic := fmt.Sprintf("%s/binary_sensor/%s/%s/config", p.cfg.DiscoveryPrefix, p.cfg.ClientID, objectID)
	p.publish(c, topic, string(payload), true)
}

func (p *Publisher) publish(c mqtt.Client, topic, payload string, retained bool) {
	t := c.Publish(topic, 1, retained, payload)
	if !t.WaitTimeout(5 * time.Second) {
		p.log.Warn("publish MQTT timed out", "topic", topic)
		return
	}
	if t.Error() != nil {
		p.log.Warn("publish MQTT", "topic", topic, "error", t.Error())
	}
}
