# 0006: Target Windows before Linux and macOS

Status: Accepted
Date: 2026-08-19

## Context

The first CORE daemon will run on a Windows machine. Daemon supervision, local
IPC, peer identity, notifications, secure storage, paths, installation, and
updates are operating-system-specific even though CORE's domain behavior should
remain portable.

Trying to prove all three desktop platforms at once would multiply Phase 1
integration work before the first vertical slice validates the product. Ignoring
portability until later would allow Windows assumptions to leak into CORE and
make Linux and macOS expensive rewrites.

## Decision drivers

- Deliver a working daemon on the user's current machine first.
- Keep CORE domain and application behavior portable from the beginning.
- Put OS differences behind narrow, testable adapters.
- Avoid claiming cross-platform support before installation, lifecycle,
  notification, permission, and recovery behavior is tested on each platform.
- Preserve one semantic client protocol across platforms.

## Considered options

### Option A: Support Windows, Linux, and macOS simultaneously

Build and release every platform adapter in Phase 1.

Benefits:

- platform assumptions are exposed immediately; and
- all supported clients can advance together.

Costs and failure modes:

- triples service, packaging, notification, secure-storage, and test scope;
- slows the first useful vertical slice; and
- encourages least-common-denominator behavior before platform needs are known.

### Option B: Build Windows first with enforced portability boundaries

Implement and validate Windows adapters first while keeping domain, application,
protocol, and test-fixture code free of Windows APIs. Add Linux next and macOS
(Darwin) after it through the same ports.

Benefits:

- fastest path to sustained use on the current machine;
- real platform behavior constrains interfaces; and
- portability is designed without pretending untested adapters exist.

Costs and failure modes:

- Windows behavior may still influence contracts unless dependency rules are
  enforced; and
- Linux/macOS differences may require revisiting an adapter port.

### Option C: Build a portable foreground application before any daemon adapter

Delay platform service integration and run CORE manually during development.

Benefits:

- fastest pure-domain experiments; and
- no installer or service work initially.

Costs and failure modes:

- does not validate the accepted presentation-independent daemon requirement;
- hides restart, login, notification, and control-surface failures; and
- creates a false Phase 1 success condition.

## Decision

Target platforms in this order:

1. Windows
2. Linux
3. macOS using the Darwin target

Windows Phase 1 implements the first non-elevated per-user daemon, protected
named-pipe transport, current-user peer binding, runtime/capability status,
installation, login startup, supervised recovery, and clean upgrade behavior.
It also defines the notification, native-status, and secret-store ports, whose
Phase 1 adapters may truthfully report unavailable. Real native notification,
capture-status/emergency-control, and platform secret-storage mechanisms enter
the Phase 2 executable slice before they handle private data or proactive
delivery. The technical spike will choose the exact per-user Windows supervision
mechanism; CORE will not become a privileged machine-wide Windows service merely
for convenience.

CORE domain, application workflow, policy, protocol, and synthetic evaluation
code cannot import Windows APIs. Platform behavior is provided through ports for:

- daemon installation and supervision;
- local endpoint creation and peer identity;
- user-session, lock, and presence signals;
- window, browser, selected-document, accessibility, and bounded screen
  observation;
- notification delivery and background status/control;
- secure configuration and secret storage;
- user data and runtime paths; and
- platform health and capability discovery.

Linux and macOS implement those same semantic ports but may expose different
capabilities and failure modes. They do not have to imitate a Windows mechanism
when the operating system provides a safer native design.

## Consequences

- Phase 1 release and acceptance tests are Windows-first.
- “Supported on Linux/macOS” is not claimed until each platform passes the same
  lifecycle, authority, privacy, reconnect, notification, and recovery suites.
- Windows-specific types remain inside infrastructure crates/adapters.
- Synthetic domain and protocol tests run on every available CI host before the
  native adapter is considered supported.
- Packaging and service installation are product behavior, not an afterthought.
- A platform may report a capability unavailable rather than silently emulating
  it with weaker security or visibility.

## Validation

- Dependency checks prove domain and application crates do not import Windows
  APIs or Windows adapter types.
- A Windows test install starts CORE for the current user without an open desktop
  client or administrative runtime authority.
- Wrong-user named-pipe connections fail before protocol commands are decoded.
- Phase 1 login, crash, restart, client-upgrade, and uninstall fixtures produce
  truthful runtime state with no orphan task, process, or endpoint.
- When observation enters Phase 2, lock, switch-user, and logout fixtures also
  prove that capture follows policy and leaves no orphaned source.
- Phase 1 capability health truthfully reports unavailable notification,
  native-status/emergency-control, and secret-store adapters rather than
  simulating success.
- When native observation and delivery enter Phase 2, notification and
  emergency-stop behavior works while the full Tauri client is closed.
- A fake platform adapter runs the complete vertical-slice fixture on non-Windows
  development hosts.

## Revisit when

- a required Windows capability cannot be implemented without elevation;
- Linux or macOS exposes a semantic gap in a supposedly portable port;
- another platform becomes the primary daily-use environment; or
- platform delivery can proceed in parallel without delaying the first validated
  slice.
