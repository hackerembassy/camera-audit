package gateway

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/gorilla/websocket"
)

const maxInspectedWebSocketMessage = 1 << 20

var webSocketHandshakeHeaders = map[string]bool{
	"Connection":               true,
	"Upgrade":                  true,
	"Sec-Websocket-Key":        true,
	"Sec-Websocket-Version":    true,
	"Sec-Websocket-Extensions": true,
	"Sec-Websocket-Protocol":   true,
	"Sec-Websocket-Accept":     true,
}

func isFrigateControlWebSocket(r *http.Request) bool {
	return r.URL.Path == "/ws" && websocket.IsWebSocketUpgrade(r)
}

func (g *Gateway) serveFrigateControlWebSocket(w http.ResponseWriter, r *http.Request) {
	upstreamURL := g.webSocketTarget(r.URL)
	headers := webSocketRequestHeaders(r)
	if g.cfg.FrigateProxySecret != "" {
		headers.Set("X-Proxy-Secret", g.cfg.FrigateProxySecret)
	}

	dialer := *websocket.DefaultDialer
	dialer.EnableCompression = true
	dialer.Subprotocols = websocket.Subprotocols(r)
	webSocketTLS := g.tls.Clone()
	webSocketTLS.NextProtos = []string{"http/1.1"}
	dialer.TLSClientConfig = webSocketTLS
	upstream, response, err := dialer.DialContext(r.Context(), upstreamURL.String(), headers)
	if err != nil {
		g.writeWebSocketUpstreamError(w, response, err)
		return
	}
	defer upstream.Close()

	upgrader := websocket.Upgrader{
		EnableCompression: true,
		CheckOrigin:       func(*http.Request) bool { return true },
	}
	if protocol := upstream.Subprotocol(); protocol != "" {
		upgrader.Subprotocols = []string{protocol}
	}
	client, err := upgrader.Upgrade(w, r, webSocketResponseHeaders(response))
	if err != nil {
		g.log.Debug("upgrade Frigate control WebSocket", "error", err)
		return
	}
	defer client.Close()

	controlID := g.manager.BirdseyeControlOpened()
	defer g.manager.BirdseyeControlClosed(controlID)

	relayErrors := make(chan error, 2)
	go func() { relayErrors <- g.relayWebSocket(client, upstream, 0) }()
	go func() { relayErrors <- g.relayWebSocket(upstream, client, controlID) }()

	<-relayErrors
	_ = client.Close()
	_ = upstream.Close()
	<-relayErrors
}

func (g *Gateway) webSocketTarget(requestURL *url.URL) *url.URL {
	target := *g.target
	switch target.Scheme {
	case "https":
		target.Scheme = "wss"
	default:
		target.Scheme = "ws"
	}
	target.Path = strings.TrimRight(target.Path, "/") + requestURL.Path
	target.RawPath = ""
	target.RawQuery = requestURL.RawQuery
	target.Fragment = ""
	return &target
}

func webSocketRequestHeaders(r *http.Request) http.Header {
	headers := make(http.Header)
	for name, values := range r.Header {
		if webSocketHandshakeHeaders[http.CanonicalHeaderKey(name)] {
			continue
		}
		for _, value := range values {
			headers.Add(name, value)
		}
	}
	headers.Set("Host", r.Host)
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		prior := headers.Values("X-Forwarded-For")
		headers.Del("X-Forwarded-For")
		if len(prior) > 0 {
			headers.Set("X-Forwarded-For", strings.Join(prior, ", ")+", "+host)
		} else {
			headers.Set("X-Forwarded-For", host)
		}
	}
	return headers
}

func webSocketResponseHeaders(response *http.Response) http.Header {
	headers := make(http.Header)
	if response == nil {
		return headers
	}
	for name, values := range response.Header {
		if webSocketHandshakeHeaders[http.CanonicalHeaderKey(name)] {
			continue
		}
		for _, value := range values {
			headers.Add(name, value)
		}
	}
	return headers
}

func (g *Gateway) writeWebSocketUpstreamError(w http.ResponseWriter, response *http.Response, err error) {
	if response == nil {
		g.log.Error("Frigate control WebSocket", "error", err)
		http.Error(w, "Frigate upstream unavailable", http.StatusBadGateway)
		return
	}
	defer response.Body.Close()
	for name, values := range webSocketResponseHeaders(response) {
		for _, value := range values {
			w.Header().Add(name, value)
		}
	}
	w.WriteHeader(response.StatusCode)
	_, _ = io.Copy(w, io.LimitReader(response.Body, 1<<20))
}

func (g *Gateway) relayWebSocket(source, destination *websocket.Conn, birdseyeControlID uint64) error {
	for {
		messageType, reader, err := source.NextReader()
		if err != nil {
			forwardWebSocketClose(destination, err)
			return err
		}
		writer, err := destination.NextWriter(messageType)
		if err != nil {
			return err
		}

		var capture *boundedCapture
		if birdseyeControlID != 0 && messageType == websocket.TextMessage {
			// Relay every byte regardless of inspection. The bounded side copy keeps
			// an unrelated or malicious control message from growing daemon memory.
			capture = &boundedCapture{limit: maxInspectedWebSocketMessage}
			reader = io.TeeReader(reader, capture)
		}
		_, copyErr := io.Copy(writer, reader)
		closeErr := writer.Close()
		if copyErr != nil {
			return copyErr
		}
		if closeErr != nil {
			return closeErr
		}
		if capture != nil && !capture.truncated {
			if cameras, ok := parseBirdseyeLayout(capture.Bytes()); ok {
				g.manager.UpdateBirdseyeLayout(birdseyeControlID, cameras)
			}
		}
	}
}

func forwardWebSocketClose(destination *websocket.Conn, err error) {
	var closeError *websocket.CloseError
	if !errors.As(err, &closeError) {
		return
	}
	message := websocket.FormatCloseMessage(closeError.Code, closeError.Text)
	_ = destination.WriteControl(websocket.CloseMessage, message, time.Now().Add(time.Second))
}

type boundedCapture struct {
	bytes.Buffer
	limit     int
	truncated bool
}

func (w *boundedCapture) Write(p []byte) (int, error) {
	remaining := w.limit - w.Len()
	if remaining <= 0 {
		w.truncated = true
		return len(p), nil
	}
	if len(p) > remaining {
		_, _ = w.Buffer.Write(p[:remaining])
		w.truncated = true
		return len(p), nil
	}
	_, _ = w.Buffer.Write(p)
	return len(p), nil
}

func parseBirdseyeLayout(message []byte) ([]string, bool) {
	var envelope struct {
		Topic   string          `json:"topic"`
		Payload json.RawMessage `json:"payload"`
	}
	if err := json.Unmarshal(message, &envelope); err != nil || envelope.Topic != "birdseye_layout" {
		return nil, false
	}
	payload := envelope.Payload
	if len(payload) > 0 && payload[0] == '"' {
		var encoded string
		if err := json.Unmarshal(payload, &encoded); err != nil {
			return nil, false
		}
		payload = []byte(encoded)
	}
	var layout map[string]json.RawMessage
	if err := json.Unmarshal(payload, &layout); err != nil || layout == nil {
		return nil, false
	}
	cameras := make([]string, 0, len(layout))
	for camera := range layout {
		cameras = append(cameras, camera)
	}
	return cameras, true
}
