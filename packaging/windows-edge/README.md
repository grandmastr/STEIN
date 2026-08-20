# Windows Edge observation packaging

Status: **production unavailable**.

The source MV3 extension and native host are protocol/adversarial fixtures. A
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

The production connection type must own the admitted named-pipe object for the
whole ingress lifetime. Comparing a borrowed numeric `HANDLE` is insufficient
because Windows can reuse that value after close; the current Rust ingress has
no production receive method until this owned transport and exact package-peer
admission are implemented together.

Caller origin, Edge ancestry, Authenticode publisher pins, and the generated
content-manifest digest are supporting evidence only. None can mint CORE
authority, and an unpacked extension can reuse a public manifest key/ID.

`Build-EdgeArtifacts.ps1` is deliberately non-installing. It requires the real
published ID/version and certificate digests, emits one exact `allowed_origins`
entry, and leaves the release identity marked blocked. It does not write the
registry, register a package, install an extension, or launch Edge.

The intended per-user lifecycle is narrowly owned:

- native host: `%LOCALAPPDATA%\STEIN\browser-host\current\stein-edge-native-host.exe`
- host manifest: `%LOCALAPPDATA%\STEIN\browser-host\current\com.stein.personal_intelligence.browser.json`
- registry: `HKCU\SOFTWARE\Microsoft\Edge\NativeMessagingHosts\com.stein.personal_intelligence.browser`
- manifest application ID: `BrowserObservationProducer` (the production AUMID
  is the certificate-derived package family name plus
  `!BrowserObservationProducer`)
- future endpoint: `\\.\pipe\LOCAL\stein-browser-observation-producer-v1`

An installer must atomically stage a signed version, validate it, then switch
`current`. Uninstall must delete the exact registry value only when it still
points to STEIN's owned manifest, reject reparse points, and remove only the
package-owned `browser-host` tree. This slice intentionally contains no install
or cleanup mutation.

JavaScript strings cannot be securely overwritten. The extension therefore
keeps raw URL/text out of browser storage and long-lived state, locally redacts
and bounds text, releases selection/content references immediately, and clears
the session on lock, revocation, disconnect, source loss, startup, or removal.
Rust frame and deserialized string storage uses explicit zeroizing wrappers.
