# Windows Edge observation packaging

Status: **production unavailable**.

The source MV3 extension, the packaged native host, and CORE's dedicated
producer endpoint are implemented. A
release must not report `P2-BROWSER` healthy until all of these independent
facts are proven on the installed Windows user account:

1. Microsoft Edge Add-ons has issued the exact extension ID and version.
2. The installed selected profile has exactly that store-managed extension
   tree, with no developer/unpacked or duplicate version location, and its
   content manifest matches the signed release manifest.
3. Edge launched the signed native host directly from its package-owned path,
   with the exact signed-package-family-name plus
   `!BrowserObservationProducer` token/AUMID. Microsoft documents native-host
   file-path launch and
   package identity separately, but does not guarantee that this Edge launch
   path preserves the declared application identity; a clean-VM native fixture
   is therefore required.
4. The host and CORE mutually authenticate a distinct, handle-bound,
   one-way browser-producer endpoint. The producer role cannot issue desktop or
   private client commands, and CORE reloads the current owner/session/grant/
   resource revisions for every packet.

The production connection owns the admitted named-pipe object for the whole
ingress lifetime; no borrowed numeric `HANDLE` is used as authority. CORE sends
one bounded capture plan freshly projected from current durable authority, then
accepts only bounded typed observation/source-status values while reloading the
current resource, grant, focus session, device, scope, and revisions for every
packet. No private-client command or observation response exists on this port.

Caller origin, Edge ancestry, Authenticode publisher pins, and the generated
content-manifest digest are supporting evidence only. None can mint CORE
authority, and an unpacked extension can reuse a public manifest key/ID.

`Build-EdgeArtifacts.ps1` is deliberately non-installing. It requires the real
published ID/version, certificate digests, exact installed package PFN/version,
and exact package-owned host path/digest. It emits one exact `allowed_origins`
entry and leaves release provenance blocked.

`Install-EdgeArtifacts.ps1` then validates that exact package, application ID,
host bytes, Authenticode publisher, and extension origin before atomically
switching the owned per-user manifest metadata and the one HKCU default value.
It does not install an extension/package or launch Edge. `Uninstall-EdgeArtifacts.ps1`
removes that default value only when it still points to the exact STEIN-owned
manifest, rejects reparse points, and deletes only the validated
`%LOCALAPPDATA%\STEIN\browser-host` metadata tree.

The intended per-user lifecycle is narrowly owned:

- native host: the exact installed MSIX path
  `<Package.InstallLocation>\bin\stein-edge-native-host.exe`
- host manifest: `%LOCALAPPDATA%\STEIN\browser-host\current\com.stein.personal_intelligence.browser.json`
- registry: `HKCU\SOFTWARE\Microsoft\Edge\NativeMessagingHosts\com.stein.personal_intelligence.browser`
- manifest application ID: `BrowserObservationProducer` (the production AUMID
  is the certificate-derived package family name plus
  `!BrowserObservationProducer`)
- future endpoint: `\\.\pipe\LOCAL\stein-browser-observation-producer-v1`

The installer records
`runtime_package_identity_admission=not_run_requires_direct_edge_launch_fixture`.
Neither successful packaging nor registration upgrades capability health. The
remaining installed fixture must launch the host directly from Edge and prove
that Windows reports the exact PFN plus `!BrowserObservationProducer`; until
then `P2-BROWSER` remains **NOT RUN** and production availability remains false.

JavaScript strings cannot be securely overwritten. The extension therefore
keeps raw URL/text out of browser storage and long-lived state, locally redacts
and bounds text, releases selection/content references immediately, and clears
the session on lock, revocation, disconnect, source loss, startup, or removal.
Rust frame and deserialized string storage uses explicit zeroizing wrappers.
