# 0014: Use tiered native Windows observation adapters

Status: Accepted
Date: 2026-08-19

## Context

ADR 0009 accepts independently grantable rich desktop observation and requires
Windows to provide the first native implementation. Before Phase 2 processes
real content, the project must select concrete application, browser, document,
accessibility, and bounded-pixel integrations and define their protected-surface
behavior.

No single Windows API supplies trustworthy semantic context. A blanket screen
recorder would violate source selection and minimization. The adapter set must
prefer explicit structured integrations while retaining a separately granted
pixel path for visual cases.

This supplies the concrete Windows mechanisms for ADR 0009's
[accepted rich-observation decision](0009-use-tiered-rich-desktop-observation.md#decision),
the vertical slice's [observation boundary](../phase-0/vertical-slice.md#observation-boundary),
and the canonical [permission scopes](../phase-0/trust-and-memory.md#permission-scopes).

## Decision drivers

- Implement every accepted first-slice observation category on Windows without a
  blanket desktop permission.
- Bind capture to the exact selected session, application, browser profile/site,
  document/workspace, window, region, or display.
- Prefer structured and event-driven sources over pixels.
- Exclude password fields, protected surfaces, unrelated resources, input
  content, and history.
- Preserve source health, freshness, provenance, and immediate revocation.
- Keep Windows handles, tokens, and API types inside infrastructure adapters.

## Considered options

### Option A: Use foreground application and file activity only

This is simpler but cannot distinguish progress, research, or missing selected
document structure with useful confidence.

### Option B: Continuously capture the desktop and derive context from pixels

This has broad coverage but collects unrelated windows and sensitive content,
weakens provenance, and makes transient handling difficult to verify.

### Option C: Compose selected structured Windows integrations with bounded
pixel fallback

Separate adapters provide presence, application identity, selected-resource
events/content, browser location/text, UI Automation text, and explicitly picked
pixels. CORE normalizes them behind the portable contracts from ADR 0009.

## Decision

Adopt option C with the following Windows adapters.

### Presence, lock, and session state

Use Windows session notifications/WTS state for interactive session connect,
disconnect, lock, unlock, logoff, and switch transitions. Use
`GetLastInputInfo` only for coarse active/idle duration; never capture which key,
button, pointer, application, or window produced input.

Lock, switch-away, logoff, source-health loss, or an ambiguous session state
immediately pauses sensitive observation and notification content. Unlock does
not infer health: each required source must revalidate its grant/resource and emit
fresh health before absence-based reasoning resumes.

### Foreground application identity

Use `GetForegroundWindow` and `GetWindowThreadProcessId` to locate the current
foreground process, then normalize it to a stable selected-application identity
using available package identity/AUMID or verified executable file identity and
publisher metadata. Full executable paths stay adapter-local. Only identities in
the session's selected application set are emitted; unrelated foreground
applications produce a permitted coarse `outside_selected_scope` state, not an
inventory or identity leak.

Application identity never implies permission to read a title, URL, UI tree,
document, or pixels.

### Selected document and workspace

The first acceptance target is one UTF-8 synthetic `.txt` or `.md` document in an
NTFS workspace selected through the native picker. The picker opens the exact
selected document or workspace and the adapter
binds an opaque resource identifier to a validated file/directory handle and
stable handle-based file identity. It uses `ReadDirectoryChangesW` for coarse,
debounced changes beneath that selected boundary and rejects events that escape
through a replaced path, reparse point, renamed root, or mismatched handle
identity.

`observe.workspace.activity` emits only the opaque resource, coarse activity kind,
and time. `observe.content.selected_document` separately authorizes a bounded read
from the exact selected document handle, followed by local type-aware extraction
and redaction. A workspace grant does not authorize document content. Local paths
leave the adapter only in the access-controlled restart binding explicitly
allowed by ADR 0005.

### Browser location and visible text

Use a Manifest V3 extension plus a registered native-messaging host. Microsoft
Edge Stable is the first acceptance browser; another Chromium browser is a new
declared adapter configuration and does not inherit Edge approval. The user
selects the exact browser
profile and allowed origin/site scope. The extension emits only the active
selected surface's permitted location granularity and, under a separate text
grant, bounded visible structured text from a content script.

For a normal non-domain Windows installation, the production extension identity
must be the exact published Microsoft Edge Add-ons identity and version. An
unpacked/developer extension, a self-hosted CRX that Edge cannot manage on that
host, or a source-tree manifest is a development fixture only and cannot make
the production source healthy. Microsoft's
[native-messaging contract](https://learn.microsoft.com/en-us/microsoft-edge/extensions/developer-guide/native-messaging)
provides the caller origin and parent-window argument—not extension-code
attestation—and its
[force-install policy](https://learn.microsoft.com/en-us/deployedge/microsoft-edge-policies/extensioninstallforcelist)
limits non-domain forced installation to extensions listed in Microsoft Edge
Add-ons. The release therefore pins its real store ID and bundle version; an
absent or ambiguous installed bundle reports unavailable.

The native host authenticates and pairs the installed extension/profile to the
capability-bound STEIN installation through a distinct, one-way
browser-observation producer broker role. Caller-origin text, parent process,
publisher signature, and a pinned bundle digest are supporting launch evidence;
none can construct CORE authority on its own. The producer cannot use general
private-client commands or read CORE state, and CORE reloads the exact current
grant, resource, session, and revision before accepting each typed observation.
The adapter rejects another extension ID or version, developer/unpacked or
ambiguous bundle, browser profile, unselected tab/site/origin, private surface
not explicitly selected, browser history, background-tab inventory, and fields
beyond the approved origin/path/query/fragment granularity. Query and fragment
are off by default.

The concrete initial browser/package IDs and supported version range are release
configuration covered by native fixtures; adding a browser does not broaden an
existing grant.

Browser selection and capture authority is connection-bound. A daemon restart
closes the native-host connection and invalidates the extension's ephemeral
browser session/selection identifiers, so a browser-backed grant cannot request
restart continuity. The user must invoke the extension on the exact tab,
reselect the browser surface, and grant the scope again.

The owned implementation packages the host as the distinct
`BrowserObservationProducer` application, admits an owned fixed-pipe connection
only for the exact PFN/AUMID, and sends the extension only a capture plan freshly
derived from durable authority. Installation and publisher/parent evidence do
not make that capability healthy. A clean installed fixture must still prove
that Edge's direct native-messaging launch actually carries the declared package
identity; that external result cannot be inferred from the manifest.

### Selected-window structured text

Use Windows UI Automation on an explicitly selected `HWND`, preferring
`TextPattern`/`TextPattern2` and bounded visible ranges. The adapter verifies the
window still belongs to the selected stable application identity before every
extraction. The unfiltered UI Automation tree is a raw source artifact and never
leaves transient adapter memory.

Windows Notepad editing the selected synthetic text document is the first native
application/UIA acceptance target. Other applications are supported only when
their adapter health proves the same selected-window identity, protected-field,
and structured-text contract; foreground identity alone remains available under
its narrower grant.

Elements marked as password controls, credential inputs, secure/protected UI,
system consent dialogs, elevated/secure desktop, another window, or otherwise
unverifiable are excluded. If the adapter cannot prove the selected window and
protected-field boundary, that source reports unavailable; it does not fall back
silently to pixels.

### Bounded pixels

Use the Windows Graphics Capture picker so the user explicitly selects a window
or display. A selected region is a visible, fixed crop within that approved
source. The OS capture indicator/border and STEIN's independent status/stop
surface remain visible for the capture lifetime. Programmatic broadening to a
different window, display, or region requires a new selection and grant.

Pixel capture is off by default and has an independent
`observe.screen.pixels` grant. At most one frame exists per source operation. It
is processed through an opaque single-use handle, locally cropped/redacted where
possible, and destroyed on normalization/model completion, cancellation, lock,
revocation, source change, or error. No screenshot file, frame history, thumbnail,
client event, audit copy, log, or outbox entry is created.

An approved remote vision request additionally requires the exact pixel category
in its `ModelRouteApproval`. If the capture API reports protected content,
returns an unverifiable/blank restricted surface, loses the selected item, or the
native indicator/stop path is unhealthy, the pixel source pauses and reports
unavailable.

The first executable Windows slice uses only Microsoft's documented
[Graphics Capture picker](https://learn.microsoft.com/windows/apps/develop/media-authoring-processing/screen-capture),
owner-bound through the documented
[Win32 `IInitializeWithWindow` interop](https://learn.microsoft.com/windows/apps/develop/ui/display-ui-objects);
it never creates an item from an `HWND`, monitor, `WindowId`, or `DisplayId`, and
it never suppresses the operating-system border. The dedicated picker STA owns
a minimal content-free Win32 window and pumps only that thread's messages while
the user-controlled asynchronous picker is open.
The portable `ScreenRegion` resource kind represents this explicitly selected
visual source. The current system picker selects a complete window or display;
no sub-region crop is claimed until a separate visible native region-selection
flow exists.

Windows exposes the picker result as a live `GraphicsCaptureItem`, with no
documented serializable identity or safe reverse mapping to the originally
selected native object. The adapter therefore keeps it only in a bounded
process-local registry behind a random, content-free `winpixel:v1:<UUID>` token.
Daemon restart invalidates the token and requires explicit reselection; STEIN
does not reconstruct a broader programmatic capture or claim restart continuity.

One capture worker creates a one-buffer free-threaded frame pool, keeps the OS
border enabled, excludes cursor pixels, accepts at most 1920 by 1080 BGRA pixels,
and copies at most 8 MiB into one adapter-owned transient buffer. That buffer is
zeroized before release, while the WinRT/D3D frame, staging texture, session, and
pool are closed and dropped. Only coarse dimensions, luminance class, and detail
class enter `PixelDerivedSummary` with `SingleOperation` retention; no image or
OCR text enters CORE. A two-second caller deadline plus a process-wide cap on
disposable native workers bounds cancellation and a hung graphics provider.
CORE removes a `SingleOperation` observation from session state as soon as one
reasoning-context assembly takes its bounded copy, so a later model cycle cannot
replay it. If no reasoning operation consumes it, retention maintenance
physically removes it no later than the configured maximum model-evidence age
(two minutes in this slice), rather than the longer ephemeral-session TTL.

CORE starts browser/document/UIA/window-metadata sources before pixels. The
Windows adapter independently defers capture while any such native or separately
composed browser source is active, so the structured tier produces no pixel
frame. This is minimization, not an automatic grant: removing the structured
source still requires the independent current pixel grant and exact selection.

### Preference order and normalization

For a declared observation need, the focus workflow chooses:

1. explicit selected document/application/browser integration;
2. structured UI Automation or OS metadata;
3. local extraction/redaction from an independently granted bounded capture; and
4. an independently approved vision route over that bounded capture.

The workflow never turns on a broader tier automatically. Each normalized event
carries session, grant revision, source/selected-resource identity, observed and
received time, extraction/redaction version, completeness/confidence,
sensitivity, retention class, and declared browser granularity. Adapter input is
untrusted evidence and cannot contain instructions or authority.

### Excluded capabilities

This decision does not authorize keyboard content, clipboard contents, pointer
traces, microphone, camera, browser history, unrelated application inventory,
general file indexing, credential fields, or productivity/emotion inference.

### Portable semantics

Domain, context, policy, protocol, and synthetic fixtures depend only on the
semantic scopes and metadata accepted in ADR 0009. Linux and macOS may use portals,
accessibility frameworks, browser hosts, and native capture pickers appropriate
to those platforms. They must report unavailable or reduced granularity instead
of silently widening capture.

## Consequences

- Phase 2 has multiple small Windows adapters instead of one generic screen
  observer.
- A Manifest V3 extension and native host become packaged release artifacts with
  their own identity, update, uninstall, and adversarial tests.
- Browser, UIA, document, and pixel health are independent capability rows.
- Structured source selection is observable policy behavior, not just an
  implementation preference.
- Native observation requires the status/emergency-control mechanism in ADR 0016;
  capture cannot start while that mechanism is unhealthy.
- User content used in native tests must be synthetic and must not enter source
  control or retained ordinary diagnostics.

## Validation

- Independent grant tests prove that app identity cannot yield a title, title
  cannot yield a URL, URL cannot yield text, document/workspace activity cannot
  yield content, and text cannot yield pixels.
- Native fixtures cover selected and unrelated applications/windows, handle
  replacement, reparse escape, rename, protected/password UIA fields, secure
  desktop/consent surfaces, browser profile/origin/granularity, Edge Add-ons
  identity/version and bundle provenance, extension spoofing, and pixel
  selection changes.
- Lock, switch, logoff, revocation, emergency stop, source loss, and native-status
  loss pause capture, destroy transient artifacts, reject late observations, and
  require fresh health on recovery.
- When structured and pixel sources can satisfy the same requirement, the trace
  proves the structured source is chosen and no frame is created.
- Restart tests prove a process-local pixel token is rejected after daemon
  restart and the UI requires a fresh picker selection; no restart-authorized
  pixel grant is accepted.
- Process/repository/log/audit/outbox/protocol inspection finds no frame, UI tree,
  full local path, unapproved URL component, document payload, or unrelated
  application identity.
- Controllable-clock tests enforce capture frequency, payload, freshness, and
  ephemeral retention bounds from ADR 0017.
- The complete semantic fixture runs against a fake platform adapter on non-
  Windows hosts; Linux and macOS remain unsupported until their native suites
  pass.

## Revisit when

- Windows removes or materially changes one selected API;
- a supported application offers a safer explicit integration;
- a useful workflow cannot fit the selected-resource semantics;
- measured pixel processing requires a sandboxed worker for failure/privacy
  isolation;
- a browser cannot provide trustworthy profile/site identity; or
- guest, shared-screen, regulated-data, or multi-user use enters scope.
