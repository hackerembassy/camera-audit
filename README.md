# Camera access audit

`camera-audit` records who accesses Frigate and which clients consume its bundled go2rtc streams. It also publishes state-only Home Assistant MQTT sensors so people in camera-equipped rooms can be warned when an unexpected viewer connects.

## What it observes

- Authenticated Frigate activity from the trusted Authentik username header.
- MSE and jsmpeg WebSocket lifetimes at the Frigate gateway.
- WebRTC signaling correlated with go2rtc consumer sessions.
- go2rtc's current consumer inventory from `/api/streams`; `/api/streams.dot`, the source for `/net.html`, is retained only as a credential-sanitized diagnostic graph.
- Frigate and Home Assistant `latest.jpg` refreshes as renewable 75-second live-view leases. Repeated smart-streaming frames become one audit session rather than one row per image.
- Birdseye as a composite view. An active Birdseye viewer conservatively activates every configured `birdseye_cameras` room.

Historical recordings, review thumbnails, event snapshots, and clips do not activate privacy alerts.

## Identity limits

Frigate browser requests passing through Authentik have an exact username. WebRTC media bypasses the HTTP gateway after signaling, so its go2rtc session is marked `correlated`. The standard Home Assistant Frigate integration calls Frigate using shared backend credentials and does not pass the HA user; those accesses are deliberately recorded as `Home Assistant`.

## Deployment

1. Copy `config.example.yaml` to `config.yaml` and replace networks, camera names, and exclusion rules.
2. Add the service from `compose.example.yaml` to the Docker network that contains Frigate.
3. Change the Authentik proxy provider upstream from Frigate to `http://camera-audit:8080`.
4. Ensure Authentik sends `X-authentik-username`, and set `trusted_proxies` to the actual outpost/proxy CIDR. Requests from other networks cannot use identity headers or access `/audit/`.
5. Configure Frigate proxy authentication as before. The gateway preserves the Authentik headers while forwarding to port 8971.
6. Point the Home Assistant Frigate integration at the audit gateway if its HTTP snapshot and WebRTC signaling accesses must be observed. Its RTSP sessions on port 8554 are still discovered through go2rtc.
7. Keep Frigate ports 5000, 8971, and go2rtc port 1984 off the host network. Restrict RTSP 8554 to known service networks; expose WebRTC 8555 only where required.
8. Import `home-assistant/privacy-alert-blueprint.yaml`, select each camera's discovered binary sensor, and configure the speaker/light/notification action for its room.

The dashboard is at `/audit/`. Any user authenticated by Authentik can see current consumers and history. Health endpoints are `/healthz` and `/readyz`.

The daemon strips Authentik/forward-auth identity headers and forwarded client addresses from any request that does not originate in `trusted_proxies`. Authentik itself must also overwrite, rather than append to, identity headers received from browsers.

## Exclusions

Rules are evaluated in order and can match stream glob, remote CIDR, protocol, and user-agent regular expression. An excluded connection is still written to history with the matching rule, but it does not activate MQTT privacy state. Producers such as camera and doorbell sources are never counted because only go2rtc `consumers` are audited.

Home Assistant is not excluded by default: viewing through HA should warn the room even though the individual HA user cannot be identified.

## MQTT behavior

For each observed camera, MQTT Discovery creates an occupancy-class binary sensor named `<camera> external viewer active`. Only `ON`, `OFF`, and availability are published—never usernames, IP addresses, or counts. State turns on immediately and clears after 30 uninterrupted seconds without an unsuppressed viewer. The blueprint triggers only on a real `off` to `on` transition.

## Local development

```sh
go test ./...
go vet ./...
go run ./cmd/camera-audit -config config.yaml
```
