# 0003: Version the typed client protocol

Status: Accepted
Date: 2026-08-19

## Context

The React/Tauri client and CORE daemon are independent processes with different
lifecycles and potentially different versions. The client needs authenticated
commands, queries, authoritative snapshots, view-event subscriptions,
cancellation, health, reconnect, and compatibility behavior.

Ad hoc local IPC would make transport details the application contract. A
network-first protocol would expose an unnecessary listener and solve remote
deployment problems the first slice does not have.

## Decision drivers

- Make Rust/TypeScript compatibility testable.
- Keep client semantics independent of Tauri and future transports.
- Use commands, queries, and events with distinct authority semantics.
- Support structured errors, cancellation, idempotency, and correlation.
- Derive local peer identity from an OS-protected endpoint rather than trusting
  an actor claimed in a payload.
- Reconnect to daemon-owned state without treating missed client events as lost
  domain state.
- Permit additive evolution without silently accepting incompatible behavior.
- Avoid an untyped method-name plus arbitrary JSON payload architecture.

## Considered options

### Option A: Ad hoc local IPC methods and events

Add a daemon IPC method or event whenever the UI needs behavior, using local DTOs
and assumed lockstep releases.

Benefits:

- lowest setup cost; and
- natural use of the first transport.

Costs and failure modes:

- inconsistent error, cancellation, identity, and version behavior;
- transport types become domain contracts;
- compatibility failures appear only at runtime; and
- a future client requires reverse-engineering UI-specific calls.

### Option B: A typed, versioned application protocol over protected local IPC

Define a closed set of typed command, query, result, error, and view-event DTOs
with common metadata and compatibility rules. Serialize framed JSON over an
OS-protected per-user local endpoint. The Tauri Rust backend is the first client
adapter; the React webview does not connect to CORE directly.

Benefits:

- explicit semantics and cross-language fixtures;
- transport remains replaceable;
- privacy and authority metadata is consistent; and
- no network service is required.

Costs and failure modes:

- endpoint discovery, peer authentication, framing, DTO mapping, and version
  fixtures add work;
- careless code generation could expose domain internals; and
- excessive envelope fields could burden simple calls.

### Option C: Adopt a network RPC or event protocol immediately

Use gRPC, JSON-RPC, HTTP, WebSocket, or another network-oriented framework even
inside the first desktop deployment.

Benefits:

- mature transport tooling; and
- direct path to remote or multi-process clients.

Costs and failure modes:

- ports, certificates or tokens, remote authentication, reconnection, and
  network deployment enter the critical path;
- framework semantics may distort domain commands and events; and
- the choice precedes a remote-client requirement.

## Decision

Use a typed, versioned application protocol, serialized as size-bounded framed
JSON over authenticated per-user local IPC.

### Local transport

- Use a Unix domain socket on platforms that support it and a named pipe on
  Windows. Do not listen on loopback TCP, the LAN, or an internet interface.
- Create the endpoint in an OS-protected per-user location. Endpoint ownership
  and permissions allow only the daemon's operating-system user.
- Resolve the peer's OS identity during connection setup and bind the resulting
  authenticated actor to the protocol session. Ignore actor identity claimed in
  message payloads.
- Treat all same-user local processes as inside the first slice's client trust
  boundary. Stronger client application identity or code-signing checks require
  a later threat-model decision.
- Apply connection, frame-size, request-rate, and idle limits before decoding
  domain messages.
- The Tauri Rust backend owns this daemon connection and maps protocol views to
  React. Webview code never receives endpoint credentials or raw transport
  access.

### Same-user trust implication

For the accepted first-slice boundary, the Windows user SID is the client trust
boundary. For example, a PowerShell script, test executable, or malicious program
started under the same signed-in Windows account can attempt to open the named
pipe and speak the protocol. If it satisfies framing and version checks, CORE
treats it as the same authenticated user; it can submit whatever direct-user
commands policy permits that user to submit. Payload actor fields cannot make it
another user, but OS-user authentication alone does not distinguish the official
desktop client from another same-user process.

Stronger future options include:

- register an application key during installation and pair each additional
  client explicitly;
- verify a signed client binary/publisher before accepting sensitive commands;
- require a trusted native confirmation for new-client registration or selected
  permission mutations; or
- use a Windows application-container/capability boundary and broker, then map an
  equivalent trust design on Linux and macOS.

Registration and signing raise the bar against accidental or unapproved clients,
but cannot fully protect against malware that already controls the user's account
and can access that user's processes or credential stores. Compromise of the
signed-in OS user remains outside the first-slice threat boundary.

### Protocol shape

- Expose a statically known set of command, query, result, error, and view-event
  types.
- Decode transport input into a closed tagged union or typed endpoint before it
  reaches an application handler. There is no generic arbitrary method/body bag
  inside CORE.
- Keep protocol DTOs separate from domain entities. Mapping occurs in the client
  adapter.
- Keep internal domain events private. Client events are privacy-filtered views
  and do not convey authority.
- Use request/response for commands and queries, plus subscriptions for view
  changes.
- Open an authenticated client session with an authoritative snapshot and
  connection-scoped event cursor produced atomically. A reconnect or detected
  gap discards affected cached state and opens a new snapshot. The first version
  promises no durable replay for disconnected clients.

### Compatibility

The initial handshake exchanges:

- protocol major and minor versions supported by each peer;
- client and CORE build identifiers;
- authenticated OS user and daemon-instance identifiers;
- supported capability identifiers and relevant schema versions; and
- maximum request sizes and optional transport features.

Peers must share a supported major version. A major version changes when a
previously valid message changes meaning, a required field is removed or
reinterpreted, or an established behavior cannot be preserved.

Within one major version, minor evolution may add optional fields, new optional
capabilities, or new message variants. Unsupported commands fail with a typed
error. Unknown view-event variants are ignored only after the client records a
compatibility diagnostic and refreshes the affected current-state view.

Every message type also has a positive integer `schema_version`. A handler
explicitly supports a finite set or range; it never guesses how to interpret an
unsupported version.

### Identifiers and time

- CORE-generated aggregate, message, correlation, and causation identifiers use
  UUID version 7, represented as canonical lowercase text at the protocol
  boundary and wrapped in distinct types in Rust and TypeScript.
- Provider or operating-system identifiers remain namespaced source identifiers
  and are never accepted as CORE aggregate identifiers.
- Wall-clock instants use RFC 3339 UTC strings with an explicit `Z` offset.
- Durations and timeouts use non-negative integer milliseconds with named fields;
  code does not infer units.
- Monotonic runtime time is used internally for elapsed policy windows but is not
  serialized as a portable wall-clock instant.

### Message metadata

Commands and events carry:

- message identity and stable semantic type;
- schema version;
- issued or occurred time;
- correlation identity and optional direct causation identity;
- authenticated actor and originating component/device where relevant;
- authority references where relevant;
- sensitivity and retention classifications; and
- privacy-safe trace context.

Queries carry the actor, correlation, deadline/cancellation, and minimum metadata
needed for authorization and diagnostics. Query results identify their schema and
the revision or observation time of returned state.

The transport/session layer supplies the authenticated actor. Public protocol
DTOs may expose that resolved actor in results or audit views, but commands cannot
override it.

Authority references are opaque identifiers, not transferable bearer secrets.
Handlers always resolve their current status with the owning permission or policy
boundary.

### Reliability behavior

- Retriable state-changing commands require an idempotency key scoped to actor
  and command type.
- Aggregate updates require an expected revision.
- Requests can carry deadlines and cancellation identifiers.
- Public errors use stable codes, safe summaries, retryability, correlation, and
  optional typed details.
- Duplicate events are ignored by message identity.
- Client disconnect cancels only connection-owned requests. Accepted daemon-owned
  workflows continue until an explicit command, expiry, or policy ends them.
- Snapshot plus event-cursor setup prevents a race between initial state and
  later events. A cursor is connection-scoped, not a durable replay promise.
- There is no global ordering promise. Owners document ordering for their own
  aggregate or source stream.

Rust protocol definitions are the canonical schema source for the first client.
TypeScript bindings may be generated or maintained from those definitions, but
the dependency/tool choice requires implementation review. Checked-in
cross-language fixtures are authoritative evidence of compatibility.

## Consequences

- The first implementation must build a small protocol package, protected local
  transport, and Tauri client adapter rather than exposing domain functions
  directly.
- JSON is a transport representation, not permission to use untyped payloads in
  domain code.
- UUIDv7 and UTC timestamp parsing become shared foundational utilities.
- Client and CORE may release together, but the daemon can outlive a client
  upgrade, so incompatibility is detected explicitly.
- A future authenticated network gateway can preserve application semantics
  without exposing the local endpoint or reusing Tauri details.
- Durable subscription replay and offline command queues are not provided.

## Validation

- Golden JSON fixtures round-trip through Rust and TypeScript for every public
  message variant.
- Wrong-user peers, insecure endpoint permissions, oversized frames, connection
  floods, actor-field spoofing, and direct webview access are rejected.
- Compatibility fixtures cover matching, additive minor, unsupported message,
  unsupported schema, and mismatched major versions.
- Fuzz or property tests reject malformed identifiers, times, sizes, and tagged
  unions without panics or private error leakage.
- Public `CreateGoal` retry fixtures prove Phase 1 idempotency. Application-level
  goal-update fixtures prove expected-revision conflict behavior until a public
  update command enters scope; that command must add wire and cross-language
  conflict fixtures in the same change.
- Cancellation propagates through one model request and one adapter shutdown
  path.
- Closing and reopening the client leaves daemon-owned workflows intact and
  establishes a new authoritative snapshot/cursor pair.
- A fake non-Tauri local client can drive the same application handlers.

## Revisit when

- a remote client or second device introduces network authentication and
  transport-specific needs;
- the threat model must distinguish trusted and untrusted applications running
  as the same OS user;
- durable replay or offline command submission becomes a product requirement;
- JSON size or serialization cost is measured as material;
- schema-generation tooling cannot preserve the required Rust/TypeScript types;
  or
- identifier or compatibility behavior cannot support multi-device operation.
