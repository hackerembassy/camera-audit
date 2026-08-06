# Camera access audit

`camera-audit` records who accesses Frigate and which clients consume its bundled go2rtc streams. It also publishes state-only Home Assistant MQTT sensors so people in camera-equipped rooms can be warned when an unexpected viewer connects.

## What it observes

- Authenticated Frigate activity from the trusted Authentik username header. A rolling session retains its original start time and updates `last_seen_at` on every request.
- MSE and jsmpeg WebSocket lifetimes at the Frigate gateway.
- WebRTC signaling correlated with go2rtc consumer sessions.
- go2rtc's current consumer inventory from `/api/streams`; `/api/streams.dot`, the source for `/net.html`, is retained only as a credential-sanitized diagnostic graph.
- Frigate and Home Assistant `latest.jpg` refreshes as renewable 75-second live-view leases. Repeated smart-streaming frames become one audit session rather than one row per image.
- Historical recording playback through Frigate's timestamp, hour, event, and review VOD/clip routes as renewable `recording_playback` sessions. The camera is recorded when it is present in the URL; event and review IDs are retained in the event details when Frigate's URL does not expose the camera.
- Birdseye as a `birdseye_live` composite view. The gateway observes Frigate's proxied `/ws` `birdseye_layout` messages and activates only the room sensors for cameras currently present in the composite.

Historical recording playback is audited but does not activate privacy alerts. Review thumbnails, event snapshots, and downloaded clips that do not pass through a recognized playback route also remain non-alerting.

## Identity limits

Frigate browser requests passing through Authentik have an exact username. WebRTC media bypasses the HTTP gateway after signaling, so its go2rtc session is marked `correlated`. The standard Home Assistant Frigate integration calls Frigate using shared backend credentials and does not pass the HA user; those accesses are deliberately recorded as `Home Assistant`.

## Deployment

1. Copy `config.example.yaml` to `config.yaml` and replace networks, camera names, and exclusion rules.
2. Add the service from `compose.example.yaml` to the Docker network that contains Frigate.
   The audit container connects directly to the bundled go2rtc API at `http://frigate:1984`; no host port publication is needed when both containers share a Docker network.
3. Protect the go2rtc API with HTTP Basic authentication. For bundled go2rtc, add this under Frigate's top-level `go2rtc` configuration, using secrets appropriate to your deployment:

   ```yaml
   go2rtc:
     api:
       username: camera-audit
       password: a-long-random-secret
   ```

   Set the same values in `CAMERA_AUDIT_GO2RTC_USERNAME` and `CAMERA_AUDIT_GO2RTC_PASSWORD`. The daemon authenticates both `/api/streams` and `/api/streams.dot`; credentials are not stored in SQLite or emitted in logs. Leave go2rtc's `local_auth` at its default `false` for bundled Frigate: Frigate's own health check and nginx proxy call go2rtc over loopback without credentials, while a separate audit container is still authenticated because it is not a loopback client.
4. Change the Authentik proxy provider upstream from Frigate to `http://camera-audit:8080`.
5. Ensure Authentik sends both username and group/role headers, and set `trusted_proxies` to the actual outpost/proxy CIDR. Requests from other networks cannot use identity headers or access `/audit/`. Configure Frigate's `proxy.header_map`, `role_map`, and separator to translate those headers into `remote-user` and `remote-role`.
6. Set `frigate_url: https://frigate:8971` when Frigate's default TLS is enabled. Port 8971 is required for Frigate to enforce admin, viewer, and camera-limited custom roles; port 5000 deliberately ignores those roles and grants anonymous admin-equivalent access. For Frigate's generated self-signed certificate, explicitly enable `frigate_tls_insecure_skip_verify` only on the private Docker network. Prefer a valid certificate, optionally using `frigate_tls_ca_file` and `frigate_tls_server_name`.
7. Set `proxy.auth_secret` in Frigate and provide the same value as `CAMERA_AUDIT_FRIGATE_PROXY_SECRET` so Frigate accepts mapped identity headers only from this gateway.
8. Point the Home Assistant Frigate integration at the audit gateway if its HTTP snapshot and WebRTC signaling accesses must be observed. Its RTSP sessions on port 8554 are still discovered through go2rtc.
9. Keep Frigate ports 5000, 8971, and go2rtc port 1984 off the host network. Port 1984 must be reachable from the audit container, but should not be published to an untrusted LAN because the go2rtc API is powerful. Restrict RTSP 8554 to known service networks; expose WebRTC 8555 only where required.
10. Import `home-assistant/privacy-alert-blueprint.yaml`, select each camera's discovered binary sensor, and configure the speaker/light/notification action for its room.

The dashboard is at `/audit/`. Any user authenticated by Authentik can see current consumers and history. Frigate/viewer activity and raw go2rtc session history use separate tables so reconnect churn cannot crowd authenticated activity out of view. Both tables and the history API are ordered by `last_seen_at`; the CSV export contains all event kinds. Set `timezone` to an IANA name such as `Asia/Yerevan` to render dashboard and CSV timestamps in local time with an explicit UTC offset. SQLite storage and JSON APIs remain UTC. The timezone database is embedded in the binary, so this also works in the distroless container. Health endpoints are `/healthz` and `/readyz`.

The daemon strips Authentik/forward-auth identity headers and forwarded client addresses from any request that does not originate in `trusted_proxies`. Authentik itself must also overwrite, rather than append to, identity headers received from browsers.

### Birdseye layout

Frigate's `/live/jsmpeg/birdseye` or go2rtc request identifies the viewer and the composite stream. Its separate `/ws` control channel publishes `birdseye_layout` JSON keyed by the physical cameras currently rendered. The gateway relays all WebSocket messages unchanged, inspects only server-to-client text messages with that exact topic, and does not persist or log unrelated payloads.

`birdseye_cameras` is optional fallback data. It is used only while no active proxied control WebSocket has supplied a layout—for example with an older Frigate version or a direct RTSP Birdseye client that never opens Frigate's control socket. Leave it empty when all Birdseye viewing goes through the Frigate UI. The current layout and whether it came from `websocket`, `fallback`, or is `unavailable` are exposed by `/audit/api/v1/current`.

## Exclusions

Rules are evaluated in order and can match stream glob, remote CIDR, protocol, and user-agent regular expression. An excluded connection is still written to history with the matching rule, but it does not activate MQTT privacy state. Producers such as camera and doorbell sources are never counted because only go2rtc `consumers` are audited.

Home Assistant is not excluded by default: viewing through HA should warn the room even though the individual HA user cannot be identified.

## MQTT behavior

For each observed camera, MQTT Discovery creates an occupancy-class binary sensor named `<camera> external viewer active`. Only `ON`, `OFF`, and availability are published—never usernames, IP addresses, or counts. State turns on immediately and clears after 30 uninterrupted seconds without an unsuppressed viewer. The blueprint triggers only on a real `off` to `on` transition.

Viewer states are retained so Home Assistant recovers promptly after its own restart. On every daemon MQTT connection, `camera-audit` subscribes to `<topic_prefix>/+/viewer`, clears retained `ON` values that are not active in the current process, and then republishes current state. A graceful shutdown also publishes `OFF` for every known camera before marking the device offline. The MQTT account therefore needs subscribe permission for `<topic_prefix>/+/viewer` in addition to its existing publish permissions. A genuinely active viewer may briefly transition through `OFF` during a full daemon restart and is restored to `ON` by the first go2rtc poll.

Camera topic and discovery IDs combine a readable slug with a stable hash, so
names that slug identically (or contain only non-ASCII characters) remain
distinct. On upgrade, the daemon removes retained discovery entries created by
the older plain-slug format. If the broker is unavailable at startup, auditing
and proxying still start while the MQTT client reconnects in the background.

## Local development

For a maintainer-oriented tour of the packages, request flows, state machines,
storage model, and extension points, see [Codebase architecture](docs/architecture.md).

```sh
go test ./...
go vet ./...
go run ./cmd/camera-audit -config config.yaml
```
