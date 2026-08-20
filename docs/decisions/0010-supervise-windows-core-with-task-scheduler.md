# 0010: Supervise Windows CORE with a per-user scheduled task

Status: Accepted
Date: 2026-08-19

## Context

ADR 0001 requires the operating system to start and supervise a non-elevated
CORE daemon independently of the desktop client. ADR 0006 makes Windows the first
adapter while preserving platform-neutral lifecycle semantics.

Windows services normally run in a machine service context and their
installation commonly requires elevation. A startup-folder entry runs in the
right interactive user session but provides no useful restart or single-instance
policy. The first proof needs login startup, start/stop/status, bounded restart,
upgrade, and uninstall behavior without giving CORE machine-wide authority.

## Decision drivers

- Install and run entirely for the current user without elevation.
- Start after user logon without requiring the desktop client.
- Restart a failed daemon within a bounded policy.
- Prevent duplicate concurrent daemon tasks.
- Keep installation, upgrade, status, and uninstall scriptable and testable.
- Map the same lifecycle semantics to different native mechanisms on Linux and
  macOS later.

## Considered options

### Option A: A machine-wide Windows service

This offers strong native supervision but introduces elevation, service-account
identity, session separation, and machine-wide installation that contradict the
accepted first-user boundary.

### Option B: A Startup-folder launcher

This is simple and non-elevated, but startup is the only lifecycle behavior; it
does not provide bounded restart, truthful task state, or duplicate control.

### Option C: A current-user Task Scheduler task

Task Scheduler can launch at logon under the interactive user's token, limit
concurrent instances, expose status, and apply restart-on-failure settings while
the desktop remains closed.

## Decision

Use a current-user Task Scheduler task named `STEIN Core SID-<owner SID>` for the
Windows Phase 1 adapter. SID qualification avoids collisions between accounts
in Task Scheduler's machine-wide task namespace, while the friendly description
remains human-readable. The task runs with the interactive user's token and
limited run level, starts at logon and immediately after installation, ignores a
duplicate start, and uses a bounded restart-on-failure policy.

The task invokes a small installed command launcher. That launcher restarts a
non-zero CORE exit quickly within a bounded count; Task Scheduler's native
restart-on-failure setting is a slower second tier if the task action itself
fails. Neither supervisor owns domain state.

The installer copies versioned proof binaries into `%LOCALAPPDATA%\STEIN\bin`,
registers or replaces only that task, starts it, and creates a current-user
desktop shortcut for the presentation client. Upgrade stops CORE through its
typed protocol when possible, stops the task as a fallback, replaces the known
files, and restarts the task. Uninstall unregisters only the named task and
removes only the explicit STEIN install files; user data is preserved unless a
separate remove-data option is requested.

CORE still enforces one daemon per user through first-instance named-pipe
creation. The scheduled task is the Windows lifecycle adapter, not domain
authority, and no Windows task type enters CORE domain/application contracts.

## Consequences

- The proof can install without administrator rights and run in the same user
  context as its protected named pipe and desktop client.
- Task Scheduler availability and current-user registration become Windows
  installation prerequisites.
- A logged-out user has no running CORE process in this phase.
- Linux and macOS must implement equivalent login startup, supervision, status,
  upgrade, and uninstall semantics through their native adapters.

## Validation

- Install from a non-elevated shell and show the registered task uses the current
  interactive user and limited run level.
- Close every presentation client and show the task keeps CORE running.
- Trigger the installed launcher's synthetic one-shot failure path and show a
  bounded restart with a new daemon instance while the Task Scheduler action
  remains active; inspect the task's native restart policy as the second tier.
- Run installation twice and show only one task and one daemon remain.
- Upgrade and uninstall leave no orphan task, process, or pipe endpoint.

## Revisit when

- Task Scheduler cannot provide reliable failure restart on a supported Windows
  version;
- CORE must run before interactive logon or across user sessions;
- a packaged-app lifecycle offers an equally testable non-elevated supervisor;
  or
- enterprise deployment requires managed machine-wide installation.
