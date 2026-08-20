# STEIN Microsoft Edge observation extension

This Manifest V3 extension selects only the tab on which the user invokes the
extension action. It has no host allowlist, browser-history permission, `tabs`
inventory permission, persistent content script, or incognito access. The
temporary `activeTab` grant is narrowed again to the exact selected tab, window,
site, origin, and CORE-supplied capture plan.

Source checkouts are intentionally inert: `extension-config.js` contains an
unresolved release-ID token. `packaging/windows-edge/Build-EdgeArtifacts.ps1`
must generate a release directory with the exact Microsoft Edge Add-ons ID.

The native host currently refuses to read content because CORE has no dedicated
OS-authenticated browser-producer admission. Edge's caller-origin argument and
signed parent image are useful evidence, but do not prove that an unpacked
extension with the same manifest key is the release-managed extension. Do not
install or claim `P2-BROWSER` until the broker seam documented by the packaging
README and the packaged native fixtures pass.
