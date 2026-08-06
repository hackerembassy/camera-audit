# Codebase architecture

This document is the maintainer's map of `camera-audit`. The root
[README](../README.md) describes behavior and deployment; this guide explains
where that behavior lives and which invariants must be preserved when changing
it.

## System boundary

`camera-audit` sits in two data paths:

1. Authentik sends Frigate HTTP and WebSocket traffic through the gateway. This
   path provides an exact username for browser activity and lets the daemon
   recognize snapshot, playback, MSE, jsmpeg, and WebRTC-signaling routes.
2. The audit manager polls go2rtc directly. This path sees the media consumers
   that remain after HTTP signaling has finished, but usually has only network
   and user-agent identity.

Short-lived signaling observations are correlated with newly appearing go2rtc
consumers. The resulting sessions and gateway activity are written to SQLite.
Unsuppressed live sessions are reduced to per-camera privacy state and published
to Home Assistant over MQTT.

```text
browser / Home Assistant
          |
          v
  Authentik proxy ---- trusted identity headers
          |
          v
  gateway package ---- route audit + /audit API ---- SQLite
          |                         ^
          v                         |
       Frigate                 audit manager <---- go2rtc polling
                                      |
                                      v
                               MQTT publisher
                                      |
                                      v
                               Home Assistant
```

## Package map

| Path | Responsibility |
| --- | --- |
| `cmd/camera-audit` | Process assembly, signal handling, and graceful shutdown. |
| `internal/config` | YAML defaults, environment expansion, and validation. |
| `internal/gateway` | Authentik trust boundary, Frigate reverse proxy, route recognition, WebSocket relay, dashboard, JSON API, and CSV export. |
| `internal/go2rtc` | Bounded, authenticated reads of `/api/streams` and the diagnostic DOT graph. |
| `internal/audit` | In-memory reconciliation, identity classification/correlation, leases, Birdseye layout, privacy state, and retention scheduling. |
| `internal/telegram` | Delayed, grouped Telegram summaries for newly started recording playback leases. |
| `internal/store` | SQLite schema, lifecycle writes, history queries, startup recovery, and pruning. |
| `internal/mqttpub` | MQTT discovery, retained state, availability, reconnect recovery, and shutdown cleanup. |
| `internal/model` | Data transferred between the manager, store, gateway, and JSON clients. |
| `home-assistant` | Blueprint consuming the discovered privacy sensors. |

The dependency direction is deliberately simple: the command wires concrete
packages together; the gateway and MQTT publisher call the manager; the manager
owns the go2rtc client and store. There is no global runtime state.

## Request and session flows

### Authenticated Frigate request

`gateway.Gateway.ServeHTTP` first decides whether the TCP peer belongs to
`trusted_proxies`. Only then may the configured identity header and the first
`X-Forwarded-For` address be used. Untrusted requests have all known proxy
identity and forwarded-address headers removed before they reach Frigate.

Recognized camera routes are passed to `Manager.StartHTTP` before proxying and
to `Manager.EndHTTP` afterward. The manager handles them in one of three ways:

- WebSocket-like live requests stay open for the request lifetime.
- Repeated snapshots and recording playback renew an inactivity lease, avoiding
  one database row per image or HLS request.
- WebRTC signaling is recorded as an instantaneous event and placed in a
  15-second correlation window for the polling path.

Recording playback is intentionally auditable but never privacy-active.

### go2rtc reconciliation

Every `poll_interval`, the manager reads go2rtc's consumer inventory and keys a
session by `camera/connection-id`. A key whose protocol, address, or user agent
changes is treated as a reused connection ID: the old event is closed and a new
one is opened. A missing consumer needs two successful polls before closure so
a single incomplete snapshot does not create reconnect churn.

Every successful inventory updates the active session's exact in-memory
`last_seen_at`. Open sessions are checkpointed to SQLite together in one
transaction every five minutes. A disconnect, reused connection ID, outage
boundary, or graceful shutdown writes the final observed time immediately;
`ended_at` records when disappearance was detected and may therefore be later.
The dashboard overlays active history rows with the in-memory value between
checkpoints.

A failed poll marks current state stale but does not immediately end sessions.
On the first successful poll after an outage, all pre-outage sessions are closed
before rebuilding state because continuity cannot be proven. `/readyz` follows
this freshness flag; `/healthz` only reports that the process is serving.

The diagnostic DOT graph is refreshed by an independent loop. A missing or slow
graph endpoint therefore cannot delay consumer reconciliation or privacy state.

### Identity and suppression

Classification rules are evaluated in configuration order, and the first match
wins. A rule can match stream glob, protocol, remote CIDR, and user-agent regex.
Rules assign a service identity and independently decide whether a session is
suppressed from privacy alerts. Suppression never removes audit history.

An exact person identity observed during MSE, WebRTC, or Birdseye signaling may
replace the generic identity of a matching go2rtc consumer. This is explicitly
marked `correlated`, not `exact`, because signaling and media are separate
connections. Service signals are allowed broader matching because backend
integrations commonly change connection details.

### Privacy state

Once per second, `Manager.tick` combines three live sources:

- current go2rtc consumers;
- request-lifetime HTTP/WebSocket observations;
- renewable snapshot/Birdseye leases that opt into privacy.

Suppressed sources are excluded. A Birdseye source is expanded into the cameras
reported by an active Frigate control WebSocket, or into `birdseye_cameras` only
when no live layout is available. Privacy turns on immediately. It turns off
only after `privacy_clear_delay` with no active source, preventing reconnects
from producing noisy `OFF`/`ON` transitions.

Each active control WebSocket retains its own latest layout. If the newest
supplier disconnects, the manager returns to the newest layout supplied by a
remaining connection rather than retaining state from the closed socket.

Observer callbacks run after the manager mutex is released. Keep this property:
MQTT I/O or a future observer must never block state reconciliation.

## State ownership and concurrency

`audit.Manager.mu` protects all mutable manager state: sessions, signals,
leases, activity windows, Birdseye connections/layout, freshness, diagnostic
graph, and privacy maps. `Current` returns copies rather than exposing those
maps and slices.

The manager's `Run` goroutine owns consumer polling, ticking, and pruning. A
separate context-bound loop refreshes the optional DOT graph, while HTTP handlers
can concurrently record activity and signals. SQLite is configured for WAL mode
but limited to one open connection, giving deterministic ordering for these
small writes and avoiding SQLite writer contention. Stream freshness uses one
five-minute batch transaction rather than one autocommit update per stream poll.

The MQTT publisher has its own mutex because reconnect callbacks are controlled
by the Paho client. It snapshots state under the lock and performs publishes
after unlocking. Camera MQTT identifiers use a readable slug plus a stable hash;
the hash prevents normalized names and non-ASCII names from sharing a state topic
or Home Assistant discovery identity. An unavailable broker does not block daemon
startup because the client continues its initial connection attempts in the
background.

## Persistence model

SQLite contains two tables:

- `events` stores every audited interval or point event. `last_seen_at` is
  monotonic, is used for history ordering and retention, and can advance without
  changing the original `started_at`.
- `activity` stores the latest authenticated Frigate activity for each
  `(actor, remote_addr, user_agent)` tuple.

There is intentionally no persisted "active" state to restore. At startup,
`RecoverOpen` closes every event lacking `ended_at`; the daemon then reconstructs
truth from gateway traffic and go2rtc. This prevents a crash from leaving a
permanently active audit interval. Recovery preserves the most recent checkpointed
`last_seen_at` instead of inventing an observation at restart time.

Schema evolution currently happens in `Store.migrate`: create the latest base
tables, inspect legacy columns, apply compatible changes, then backfill. New
migrations must remain safe to run repeatedly against both new and existing
databases.

Configuration loading rejects non-positive timing values before they can reach
tickers or lease state machines. Upstream addresses must be absolute HTTP(S)
URLs without embedded credentials, queries, or fragments. Unknown YAML fields
are rejected so misspelled security or timing settings cannot silently fall back
to defaults.

## HTTP surface

| Route | Authentication | Purpose |
| --- | --- | --- |
| `/healthz` | none | Process liveness. |
| `/readyz` | none | SQLite reachable and go2rtc state fresh. |
| `/audit/` | trusted proxy plus identity | Auto-updating dashboard shell. |
| `/audit/api/v1/current` | trusted proxy plus identity | Current sessions, activity, privacy, Birdseye, and freshness. |
| `/audit/api/v1/dashboard` | trusted proxy plus identity | Combined live state and separated dashboard histories. |
| `/audit/api/v1/history` | trusted proxy plus identity | Recent events; accepts `limit`, `camera`, and `type=frigate\|recordings\|streams`. |
| `/audit/api/v1/graph` | trusted proxy plus identity | Credential-sanitized go2rtc DOT graph. |
| `/audit/export.csv` | trusted proxy plus identity | Up to 1,000 recent events, optionally filtered by `camera`. |
| all other routes | forwarded to Frigate | Proxied and audited when recognized. |

Dashboard and CSV timestamps use the configured timezone. JSON and SQLite stay
in UTC.

## Safety and privacy invariants

Changes should preserve these properties:

- Identity headers and forwarded client addresses are trusted only from an
  explicitly configured proxy CIDR.
- The browser cannot supply Frigate's `X-Proxy-Secret`; the gateway deletes it
  and writes its configured secret on the upstream request.
- go2rtc and MQTT credentials are used for outbound connections only and are
  never stored in events or emitted in normal logs.
- The DOT graph is size-limited and credential-sanitized before exposure.
- Frigate control messages are relayed unchanged. Only bounded text messages
  with the exact `birdseye_layout` topic are decoded, and payloads are not
  persisted or logged.
- MQTT contains camera-level `ON`/`OFF` state only—never identities, addresses,
  user agents, or viewer counts.
- Suppression affects alerts, not the audit trail.

## Making changes

When adding a new access route:

1. Extend `cameraAccess` or `recordingPlayback` and add table-driven gateway
   tests for positive and nearby negative paths.
2. Decide whether it is request-lifetime, instantaneous, or renewable by
   updating `httpLease` if necessary.
3. Explicitly decide whether it activates privacy and whether it creates a
   signaling correlation hint.
4. Update the behavioral README if operators need to know about it.

When adding a new live source, include it in `Manager.tick`, preserve the
immediate-on/delayed-off behavior, and add manager tests that advance explicit
timestamps rather than sleeping.

When changing JSON models, remember that field tags form the local API contract.
Keep storage timestamps UTC and perform presentation timezone conversion only
at the gateway boundary.

## Verification

Run the standard checks from the repository root:

```sh
go test ./...
go vet ./...
```

Tests use temporary SQLite databases and local HTTP/WebSocket test servers; they
do not require a running Frigate, go2rtc, MQTT broker, or Home Assistant instance.
