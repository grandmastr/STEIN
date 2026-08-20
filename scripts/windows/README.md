# STEIN Windows proof lifecycle

Run these launchers from a normal, non-administrator Command Prompt or
PowerShell window. The `.cmd` entrypoints start Windows PowerShell with a
process-scoped execution-policy bypass, which is required on machines whose
effective policy is `Restricted`. They do not change the user's or machine's
PowerShell policy.

## Build and package

From the repository root:

```text
scripts\windows\build.cmd
scripts\windows\package.cmd
```

The package is rebuilt through a clean staging directory at `artifacts\windows`.
Its manifest records the size and SHA-256 hash of every packaged file.
Installation verifies all manifest entries before stopping or replacing an
installed process.

## Install and test

From `artifacts\windows`:

```text
install.cmd
status.cmd
smoke-test.cmd
```

Installation is per-user and non-elevated. CORE is registered as a
SID-qualified Task Scheduler task, starts in the current user's interactive
session, remains enabled on battery, and does not depend on the desktop window.

The smoke test intentionally closes and reopens the desktop, then uses a
one-shot marker to make the installed launcher treat a drained CORE exit as a
synthetic failure. The launcher must start a new daemon instance while the
Task Scheduler action remains active; Task Scheduler's restart-on-failure policy
is the second supervision tier. The report is written under
`%LOCALAPPDATA%\STEIN` on both success and failure.

## Uninstall

```text
uninstall.cmd
uninstall.cmd -RemoveData
```

The default preserves logs, reports, and user data. `-RemoveData` is accepted
only for a directory below the current user's `LOCALAPPDATA` whose install
manifest matches both that directory and the current user SID.
