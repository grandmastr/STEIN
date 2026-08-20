# 0001: Run CORE as a per-user daemon

Status: Accepted
Date: 2026-08-19

## Context

STEIN is intended to maintain continuity whether or not a particular presentation
client is open. The first desktop client visualizes and controls STEIN, but it
must not own CORE's lifecycle, canonical state, observation, reasoning,
scheduling, or intervention behavior.

CORE could run inside the Tauri desktop process, as a Tauri-managed sidecar, or
as an independently supervised per-user daemon.

## Decision drivers

- STEIN continues authorized work when the desktop client closes, crashes, or is
  temporarily unavailable.
- Goals, permissions, working state, timers, and audit history have one canonical
  local owner independent of presentation.
- Replaceable desktop, CLI, voice, mobile, and future ambient clients can connect
  to the same runtime.
- Background capture and action state remains visible, controllable, and
  fail-closed.
- CORE remains a modular monolith even though it is deployed separately from the
  first client.
- The daemon does not acquire system-wide or elevated authority merely because
  it is persistent.

## Considered options

### Option A: Embed CORE in the Tauri Rust process

The Tauri backend constructs CORE and the React client reaches it through Tauri
IPC.

Benefits:

- one executable, installer, and lifecycle;
- no local service discovery or cross-process authentication; and
- lowest initial operational complexity.

Costs and failure modes:

- closing or restarting the desktop ends STEIN's runtime;
- canonical state and background work become coupled to one presentation;
- additional clients cannot share one continuously available runtime; and
- UI and CORE failures share a deployment lifecycle.

### Option B: Run CORE as a desktop-managed sidecar

Tauri launches and supervises a separate CORE executable.

Benefits:

- process and crash isolation from the desktop;
- a real local protocol boundary; and
- client and CORE can still ship in lockstep.

Costs and failure modes:

- CORE normally stops with its parent client;
- orphan and supervision behavior still belongs to the desktop; and
- background continuity remains presentation-dependent.

### Option C: Run CORE as a per-user daemon

The operating system supervises one CORE process for the signed-in user. Clients
connect through an authenticated local protocol and do not own its lifetime.

Benefits:

- presentation-independent continuity;
- one canonical runtime for multiple replaceable clients;
- client restart and upgrades do not inherently stop active workflows; and
- service health, resource use, and lifecycle are explicit.

Costs and failure modes:

- installation, supervision, upgrades, local authentication, version skew,
  reconnect, and recovery are first-class requirements;
- the daemon and clients can disagree about visible state unless the protocol is
  designed around authoritative snapshots;
- background capture creates a stronger trust obligation; and
- platform-specific service and notification integration must be tested.

## Decision

Run CORE as an independently supervised, per-user daemon from the first vertical
slice.

The daemon starts for the signed-in user after explicit installation/setup and
is supervised by the operating system's per-user service mechanism. It does not
run as root, as a machine-wide service, or in another user's session. One active
daemon owns that user's canonical STEIN state on the device.

The Tauri desktop application is a presentation and control client. Its Rust
backend connects to CORE through an authenticated local transport and maps the
versioned client protocol to React. Closing, crashing, or upgrading the client
does not stop CORE, revoke grants, end focus sessions, or discard canonical
state.

The first daemon listens only on an operating-system-protected local endpoint. It
does not expose a LAN or internet listener. ADRs 0003 and 0006 select a
current-user-protected Windows named pipe first, followed by platform-appropriate
local endpoints on Linux and macOS.

### Background behavior

- CORE may continue only workflows covered by current grants and policy.
- A client disconnect is not consent withdrawal. Observation ends through an
  explicit stop/revoke command, grant expiry, workflow completion, policy denial,
  or daemon shutdown.
- A focus-session grant declares whether it may survive supervised daemon
  restart. On recovery, CORE revalidates identity, expiry, scope, and policy
  before restarting an adapter.
- Restored observation sources begin unhealthy/unknown and must produce fresh
  health and evidence before absence-based reasoning resumes.
- Native notification delivery can operate without the full desktop client when
  its channel grant remains valid.
- An operation requiring interactive confirmation cannot proceed without an
  authenticated confirmation-capable client or native control surface. It waits
  within a bounded validity window or expires denied.
- If no authorized delivery channel is available, STEIN continues safe internal
  work but does not claim that an intervention was delivered.

### Visibility and emergency control

Background observation requires an independently available, OS-appropriate
status and stop path, such as a per-user status item, native capture indicator,
or service control surface. The full desktop client is not the only way to see
or stop capture.

If the required status/control surface is unavailable or cannot truthfully report
capture state, affected observation pauses or fails closed. A daemon's technical
ability to continue is not permission to operate invisibly.

## Consequences

- Phase 1 must build service installation, startup, health, authenticated local
  IPC, reconnect, version negotiation, upgrade, and recovery behavior.
- The desktop client queries authoritative snapshots after every connect or event
  gap; it never assumes that its cached view is current.
- Session and permission lifetimes are owned by CORE and cannot be inferred from
  whether a window exists.
- Native observers and delivery adapters live in or are supervised by CORE, not
  by the React client.
- CORE and the desktop can fail and update independently, so protocol
  compatibility is required even when they normally ship together.
- Background resource budgets, lock/logout behavior, and service diagnostics
  become part of the product's trust surface.
- This process boundary separates presentation failures from CORE but is not by
  itself a sandbox. Adapters running with the same user authority still require
  narrow contracts and policy checks.
- CORE remains one modular-monolith deployment. This decision does not turn its
  internal boundaries into network services.

## Validation

- Start a focus session, close the desktop client, and prove authorized
  observation, context maintenance, timers, and native delivery continue.
- Reopen the client and prove its snapshot matches daemon state without replaying
  stale local commands.
- Crash or upgrade the client without changing grants or active workflow state.
- Restart the daemon and prove only unexpired, restart-authorized workflows are
  recovered, with source health reset to unknown until fresh evidence arrives.
- Connect with the wrong OS user, stale client version, invalid credentials, or a
  copied endpoint and prove access fails without disrupting the daemon.
- Lock, switch, and log out the user session and prove capture/delivery follow
  the declared policy and never expose notification content to another user.
- Remove the background status/control surface and prove affected capture pauses
  rather than becoming invisible.
- Force native delivery and audit failures and prove CORE records truthful
  outcomes without repeated or unauthorized notifications.

## Revisit when

- a device must host more than one isolated STEIN user;
- multiple local daemons require discovery or coordination;
- a capability requires stronger sandbox or privilege separation;
- a trusted remote client or second device requires a network gateway;
- operating-system constraints make one daemon unsuitable for observation or
  notification delivery; or
- measured reliability shows that runtime state needs a different supervision or
  recovery model.
