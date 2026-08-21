# 0011: Require an OS capability broker for private client access

Status: Accepted
Date: 2026-08-19

## Context

ADR 0003 accepts the signed-in operating-system user as the Phase 1 local client
trust boundary. On Windows, any process running under that user's SID can attempt
to open CORE's named pipe and, if it speaks the protocol, submit commands that
CORE treats as direct-user commands. That was sufficient for the Phase 1 daemon
and handshake proof. It is not sufficient once Phase 2 exposes selected document
content, model-route configuration, permissions, intervention history, or other
private state.

The user selected the strongest of the previously listed hardening directions:
bind sensitive client access to an operating-system application capability and a
broker, using an exact signed MSIX package identity and AppContainer SID first.
Linux and macOS need equivalent semantics rather than a Windows-shaped API.

This decision narrows client access. It does not change the accepted assumption
that malware which already controls the user's account, processes, or credential
stores is outside the first-slice threat boundary.

This closes the hardening gate in the
[Phase 0 implementation package](../phase-0/README.md#implementation-gate),
refines ADR 0003's
[same-user trust implication](0003-version-the-typed-client-protocol.md#same-user-trust-implication),
and preserves the
[supported authority context](../phase-0/trust-and-memory.md#supported-authority-context).

## Decision drivers

- Distinguish an installed, approved STEIN client from an arbitrary same-user
  process before exposing private views or permission mutations.
- Make the binding depend on OS-verified package identity and capability state,
  not an executable path or self-asserted client identifier.
- Keep browser/webview code away from client credentials and raw daemon IPC.
- Preserve a small diagnostic surface for recovery without exposing personal
  state.
- Keep grants and policy separate from client admission: an admitted client still
  cannot mint observation, model, or delivery authority.
- Carry one portable semantic contract to Linux and macOS.

## Considered options

### Option A: Continue relying on the Windows user SID

This leaves every same-user process inside the private client boundary. It adds
no implementation work but does not meet the pre-Phase-2 hardening gate.

### Option B: Store a reusable application key

A random installation key can distinguish accidental clients, but a reusable
bearer secret is copyable and does not prove which application is presenting it.

### Option C: Verify only executable path, hash, or publisher

Publisher and file identity are useful evidence, but path checks are brittle and
publisher checks alone do not express user-approved capability. Update and test
binaries also make an allowlist difficult to operate safely.

### Option D: Use an OS capability broker and application sandbox identity

An OS-protected broker admits a packaged client only after validating package and
capability identity, then gives that connection a short-lived capability. This
adds packaging and native-test work, but makes client admission explicit and
revocable without inventing a network identity system.

## Decision

Adopt option D.

### Access classes

CORE exposes two local client classes:

1. **Diagnostic client.** A same-user peer authenticated by the protected local
   endpoint may negotiate protocol compatibility and query a content-free runtime
   and capability-health view. It cannot receive the private snapshot or event
   stream, mutate state, stop CORE, inspect identifiers that reveal personal
   activity, or access goals, identity, preferences, resources, grants, routes,
   context, interventions, outbox, or audit.
2. **Capability-bound client.** A client connection that also proves a current
   broker-issued private-client capability may access the typed private protocol,
   subject to the normal command, grant, revision, and policy checks.

The diagnostic allowlist is closed. A new query is private unless an explicit
contract review proves that every success and failure field is content-free and
safe for arbitrary same-user processes.

### Windows broker

The Windows adapter uses an exact signed MSIX package identity and AppContainer
boundary. Installation derives the expected Package Family Name (PFN) and
AppContainer SID through Windows package/AppContainer APIs. A native broker
endpoint grants client access to that exact AppContainer SID, not to an ordinary
client merely because it has the owning user SID. The daemon retains only the
endpoint ownership/control rights it needs. The broker independently validates
the calling process token's AppContainer SID, package family/identity, owning
Windows user, and expected installed publisher identity before admitting a
private session.

The package/AppContainer SID is the Windows OS capability in this decision. STEIN
does not assume a custom capability or Signed Custom Capability Descriptor (SCCD),
which would add signing/provisioning dependencies outside this local slice. A
future custom capability would require separate feasibility evidence and an ADR.

The broker is an identity/admission and transport adapter only. If Windows
packaging requires a small helper component, that helper validates the peer and
establishes connection assurance; it does not own grants, private domain state,
observation, workflow lifecycle, native status, emergency stop, notification, or
outbox delivery. Those responsibilities remain in CORE, including the in-CORE
native mechanisms selected by ADR 0016.

Successful admission produces at least 256 bits of cryptographically random,
single-use authority bound to:

- the authenticated Windows user;
- the verified package/AppContainer identity;
- the exact CORE daemon instance;
- the exact client transport connection; and
- a short broker handshake deadline.

CORE stores the authority as connection state. It is not a user permission, is
not serialized into application messages, cannot be transferred to another
connection, and expires on disconnect, daemon restart, broker rejection, or
handshake timeout. Reconnect requires fresh admission. The Tauri Rust backend
holds the native connection; React never receives the authority, broker handle,
or raw named-pipe access.

Package name text, an executable path, a claimed AUMID, a file existing under the
install directory, or the Phase 1 named-pipe SID check is not proof. The
implementation must demonstrate that the peer token is bound to the exact signed
installed MSIX PFN and derived AppContainer SID. Until that proof passes, the
client remains diagnostic-only and Phase 2 private observation remains disabled.

Development builds do not gain a production bypass. A development harness uses
a separately signed/named test package identity and derived AppContainer SID,
isolated endpoint, synthetic records, and an explicit non-production build flag.
Release binaries reject that flag and test package identity.

### Authority and lifecycle

Broker admission answers only whether this client may request private protocol
operations. CORE still resolves the authenticated user, direct-user intent,
current grants, expected revisions, and candidate-specific policy at the owning
boundary. A model, observation, event, browser extension, or broker token cannot
become a user grant.

Disconnecting the admitted client does not revoke a daemon-owned focus workflow.
Existing workflows continue only under their current grants. While no admitted
full client exists, the independently available native capture-status and
emergency-stop surface remains the control path required by ADRs 0001 and 0009.

Broker or package-validation failure prevents new private client operations and
is reported through content-free health. It does not silently downgrade a
private request onto the diagnostic surface.

### Portable semantics

The domain and client protocol see `Diagnostic` or `PrivateCapabilityBound`
client assurance, never AppContainer, package SID, AUMID, or Windows token types.
Linux and macOS adapters must provide an OS-enforced application identity and
brokered, connection-bound capability with the same failure behavior before those
platforms expose private Phase 2 views. Candidate mechanisms such as a sandbox
portal/application identity on Linux or code-signing, sandbox, and XPC audit-token
validation on macOS require platform ADRs and native adversarial suites.

## Consequences

- Phase 1's unpackaged same-user IPC remains useful for content-free diagnostics
  but cannot satisfy Phase 2 client authentication.
- Windows MSIX packaging, signing/publisher identity, PFN/AppContainer endpoint
  registration, broker startup, and upgrade compatibility become product
  behavior.
- The CLI becomes diagnostic-only in production unless a separately approved,
  capability-bound client is implemented.
- A compromised registered client can still exercise the user's allowed protocol
  surface; grants, confirmation, policy, minimization, and audit remain necessary.
- Package replacement must preserve or deliberately rotate the identity/capability
  binding without leaving the previous package authorized accidentally.
- Private-protocol errors must not reveal whether a goal, resource, route, or
  intervention exists to a diagnostic client.

## Validation

- A correctly signed and installed MSIX/AppContainer client with the exact
  expected PFN and derived AppContainer SID obtains a private session and
  exercises one private query and direct-user command.
- An unpackaged copy of the same executable, a renamed binary in the install
  directory, and a program that claims the same package/AUMID fields remain
  diagnostic-only.
- A same-SID adversarial program that speaks valid framing and protocol cannot
  obtain a private snapshot, subscription, command, shutdown, grant, or route
  operation. The shipped diagnostic CLI provides a fixed, non-mutating raw-wire
  denial proof for this boundary. It accepts no endpoint, payload, identity,
  credential, or fault input; its content-free receipt is independently bound to
  the signed candidate by the installed acceptance harness.
- A different Windows SID fails at endpoint and peer authentication before broker
  admission or domain decoding.
- A copied, replayed, expired, cross-connection, and prior-daemon capability is
  rejected without disrupting CORE.
- The webview cannot open either the CORE or broker endpoint and never receives
  capability material.
- Package upgrade and uninstall remove obsolete package/AppContainer endpoint
  registrations and leave exactly one admitted current package.
- Broker loss and validation failure produce truthful content-free health and no
  private-data fallback.
- Static and runtime diagnostics contain no capability material, private request
  fields, or package-validation secrets.

## Revisit when

- Windows packaging cannot provide a stable OS-enforced application capability;
- a second independently trusted local client must be registered;
- a CLI needs private automation under a separately inspectable approval flow;
- the threat model expands to malware controlling the signed-in account; or
- Linux or macOS exposes a semantic gap that the client-assurance contract cannot
  represent.
