import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import { webcrypto } from "node:crypto";
import { fileURLToPath } from "node:url";
import path from "node:path";

globalThis.crypto ??= webcrypto;

import {
  boundUtf8,
  buildObservation,
  buildSelectionOffer,
  encodedBytes,
  localRedact,
  standardWebLocation,
  validateCapturePlan,
} from "../policy.js";

const extensionId = "abcdefghijklmnopabcdefghijklmnop";
const extensionVersion = "0.1.0";
const selectionIdentity = Object.freeze({
  profile_binding_sha256: "11".repeat(32),
  browser_session_id: "22".repeat(16),
  selection_id: "33".repeat(16),
});

function tab(overrides = {}) {
  return {
    id: 41,
    windowId: 7,
    active: true,
    incognito: false,
    url: "https://atlas.example/research?q=private#draft",
    ...overrides,
  };
}

async function fixture(scope = "location") {
  const offer = await buildSelectionOffer(
    tab(),
    extensionId,
    extensionId,
    extensionVersion,
    selectionIdentity,
  );
  const plan = validateCapturePlan(
    {
      protocol_version: 1,
      kind: "capture_plan",
      extension_id: extensionId,
      extension_version: extensionVersion,
      scope,
      authority_epoch: 9,
      profile_binding_sha256: "11".repeat(32),
      browser_session_id: "22".repeat(16),
      selection_id: "33".repeat(16),
      tab_id: 41,
      window_id: 7,
      site_sha256: offer.site_sha256,
      origin_sha256: offer.origin_sha256,
      granularity: scope === "location"
        ? { origin: true, path: true, query: false, fragment: false }
        : { origin: false, path: false, query: false, fragment: false },
      maximum_payload_bytes: 2048,
      minimum_interval_ms: 5000,
    },
    offer,
    extensionId,
    extensionId,
    extensionVersion,
  );
  return { offer, plan };
}

test("only an explicit standard active non-private tab can be offered", async () => {
  assert.ok(
    await buildSelectionOffer(
      tab(),
      extensionId,
      extensionId,
      extensionVersion,
      selectionIdentity,
    ),
  );
  for (const candidate of [
    tab({ active: false }),
    tab({ incognito: true }),
    tab({ url: "edge://history" }),
    tab({ url: "chrome://settings" }),
    tab({ url: "file:///C:/synthetic.txt" }),
    tab({ url: "https://user:secret@atlas.example/research" }),
    tab({ id: 0 }),
  ]) {
    assert.equal(
      await buildSelectionOffer(
        candidate,
        extensionId,
        extensionId,
        extensionVersion,
        selectionIdentity,
      ),
      null,
    );
  }
  assert.equal(
    await buildSelectionOffer(
      tab(),
      "b".repeat(32),
      extensionId,
      extensionVersion,
      selectionIdentity,
    ),
    null,
  );
  assert.equal(
    await buildSelectionOffer(tab(), extensionId, extensionId, extensionVersion, {
      ...selectionIdentity,
      profile_binding_sha256: "00",
    }),
    null,
  );
  assert.equal(standardWebLocation("not a URL"), null);
});

test("capture plan binds exact extension connection tab site and origin", async () => {
  const { offer, plan } = await fixture();
  assert.ok(plan);
  for (const mutation of [
    { extension_id: "b".repeat(32) },
    { profile_binding_sha256: "90".repeat(31) },
    { tab_id: 99 },
    { site_sha256: "91".repeat(32) },
    { origin_sha256: "92".repeat(32) },
    { maximum_payload_bytes: 64 * 1024 },
  ]) {
    assert.equal(
      validateCapturePlan(
        { ...plan, kind: "capture_plan", ...mutation },
        offer,
        extensionId,
        extensionId,
        extensionVersion,
      ),
      null,
    );
  }

  assert.equal(
    validateCapturePlan(
      { ...plan, kind: "capture_plan" },
      { ...offer, active: false },
      extensionId,
      extensionId,
      extensionVersion,
    ),
    null,
  );
});

test("location excludes query fragment text background and unrelated surfaces", async () => {
  const { plan } = await fixture();
  const value = await buildObservation(plan, tab(), true, "must not travel", 1, 1_800_000_000_000);
  assert.equal(value.location.origin, "https://atlas.example");
  assert.equal(value.location.path, "/research");
  assert.equal(value.location.query, null);
  assert.equal(value.location.fragment, null);
  assert.equal(value.visible_text, null);
  assert.ok(encodedBytes(value) < 64 * 1024);
  assert.equal(await buildObservation(plan, tab({ active: false }), true, null, 2, Date.now()), null);
  assert.equal(await buildObservation(plan, tab({ id: 99 }), true, null, 2, Date.now()), null);
  assert.equal(
    await buildObservation(plan, tab({ url: "https://other.example/" }), true, null, 2, Date.now()),
    null,
  );
});

test("visible text redaction and UTF-8 bounds remove synthetic private fixtures", () => {
  const privateText = "Atlas analyst@example.test password: synthetic-secret " + "🙂".repeat(100);
  const redacted = localRedact(privateText);
  assert.doesNotMatch(redacted, /synthetic-secret|analyst@example\.test/u);
  const bounded = boundUtf8(redacted, 64);
  assert.ok(new TextEncoder().encode(bounded).byteLength <= 64);
});

test("visible text is bound to the exact injected document across navigation races", async () => {
  const { plan } = await fixture("visible_text");
  const allowedDocument = {
    text: "Synthetic visible research text",
    origin: "https://atlas.example",
    site: "atlas.example",
  };
  const value = await buildObservation(
    plan,
    tab(),
    true,
    allowedDocument,
    1,
    1_800_000_000_000,
  );
  assert.equal(value.visible_text, allowedDocument.text);
  assert.equal(value.location, null);
  assert.equal(JSON.stringify(value).includes(allowedDocument.origin), false);

  // `tab.url` is the old allowed snapshot while executeScript ran in the
  // newly committed cross-origin top document. The exact document evidence,
  // rather than a second tab snapshot, must decide admission.
  assert.equal(
    await buildObservation(
      plan,
      tab(),
      true,
      {
        text: "Cross-origin synthetic text",
        origin: "https://other.example",
        site: "other.example",
      },
      2,
      1_800_000_000_100,
    ),
    null,
  );
  assert.equal(
    await buildObservation(
      plan,
      tab(),
      true,
      { ...allowedDocument, unexpected: "private" },
      2,
      1_800_000_000_100,
    ),
    null,
  );
});

test("manifest and worker statically exclude broad or durable browser collection", async () => {
  const root = path.dirname(path.dirname(fileURLToPath(import.meta.url)));
  const manifest = JSON.parse(await readFile(path.join(root, "manifest.json"), "utf8"));
  assert.equal(manifest.manifest_version, 3);
  assert.equal(manifest.incognito, "not_allowed");
  assert.deepEqual(
    [...manifest.permissions].sort(),
    ["activeTab", "nativeMessaging", "scripting", "storage"].sort(),
  );
  assert.equal(manifest.host_permissions, undefined);
  assert.equal(manifest.content_scripts, undefined);
  const worker = await readFile(path.join(root, "service-worker.js"), "utf8");
  for (const forbidden of [
    "chrome.tabs.query",
    "chrome.history",
    "storage.local",
    "storage.sync",
    "console.log",
    "<all_urls>",
  ]) {
    assert.equal(worker.includes(forbidden), false, forbidden);
  }
  for (const required of [
    "frameIds: [0]",
    "[type='password']",
    "[contenteditable]",
    "visibilityState",
    "clearSelection",
  ]) {
    assert.equal(worker.includes(required), true, required);
  }
});
