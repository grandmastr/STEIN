import { EXPECTED_EXTENSION_ID, NATIVE_HOST_NAME } from "./extension-config.js";
import {
  buildObservation,
  buildSelectionOffer,
  validateCapturePlan,
} from "./policy.js";

const SESSION_KEY = "active_selected_surface";
const EXTENSION_VERSION = chrome.runtime.getManifest().version;
const browserSessionId = randomHex(16);
const profileBindingPromise = randomProfileBinding();

let active = null;
let generation = 0;
let focusedWindowId = null;
let pendingTimer = null;

void chrome.storage.session.setAccessLevel({ accessLevel: "TRUSTED_CONTEXTS" });

chrome.runtime.onInstalled.addListener(() => {
  void clearSelection();
});

chrome.runtime.onStartup.addListener(() => {
  void clearSelection();
});

chrome.action.onClicked.addListener((tab) => {
  void beginSelection(tab);
});

chrome.tabs.onActivated.addListener(({ tabId, windowId }) => {
  if (!active) {
    return;
  }
  if (tabId !== active.plan.tab_id || windowId !== active.plan.window_id) {
    sendContentFreeStatus("paused_background");
    return;
  }
  void collectSelectedTab();
});

chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (!active || tabId !== active.plan.tab_id) {
    return;
  }
  if (changeInfo.status === "complete" || Object.hasOwn(changeInfo, "url")) {
    void collect(tab);
  }
});

chrome.tabs.onRemoved.addListener((tabId) => {
  if (active?.plan.tab_id === tabId) {
    void clearSelection();
  }
});

chrome.windows.onFocusChanged.addListener((windowId) => {
  focusedWindowId = windowId;
  if (!active) {
    return;
  }
  if (windowId !== active.plan.window_id) {
    sendContentFreeStatus("paused_background");
    return;
  }
  void collectSelectedTab();
});

async function beginSelection(tab) {
  await clearSelection();
  const offer = await buildSelectionOffer(
    tab,
    chrome.runtime.id,
    EXPECTED_EXTENSION_ID,
    EXTENSION_VERSION,
    {
      profile_binding_sha256: await profileBindingPromise,
      browser_session_id: browserSessionId,
      selection_id: randomHex(16),
    },
  );
  if (!offer) {
    return;
  }
  const localGeneration = ++generation;
  let port;
  try {
    port = chrome.runtime.connectNative(NATIVE_HOST_NAME);
  } catch {
    return;
  }
  const candidate = { port, offer, plan: null, sequence: 0, lastSentAt: 0, generation: localGeneration };
  active = candidate;
  focusedWindowId = tab.windowId;
  port.onMessage.addListener((message) => {
    void receiveNativeMessage(candidate, message);
  });
  port.onDisconnect.addListener(() => {
    if (active === candidate) {
      void clearSelection();
    }
  });
  port.postMessage(offer);
}

async function receiveNativeMessage(candidate, message) {
  if (active !== candidate || candidate.generation !== generation) {
    return;
  }
  if (message?.kind === "cancel" && ["locked", "revoked", "source_lost"].includes(message.reason)) {
    await clearSelection();
    return;
  }
  if (candidate.plan !== null) {
    await clearSelection();
    return;
  }
  const plan = validateCapturePlan(
    message,
    candidate.offer,
    chrome.runtime.id,
    EXPECTED_EXTENSION_ID,
    EXTENSION_VERSION,
  );
  candidate.offer = null;
  if (!plan) {
    await clearSelection();
    return;
  }
  candidate.plan = plan;
  await chrome.storage.session.set({
    [SESSION_KEY]: {
      authority_epoch: plan.authority_epoch,
      selection_id: plan.selection_id,
      tab_id: plan.tab_id,
      window_id: plan.window_id,
    },
  });
  await collectSelectedTab();
}

async function collectSelectedTab() {
  const snapshot = active;
  if (!snapshot?.plan) {
    return;
  }
  let tab;
  try {
    tab = await chrome.tabs.get(snapshot.plan.tab_id);
  } catch {
    await clearSelection();
    return;
  }
  await collect(tab);
}

async function collect(tab) {
  const snapshot = active;
  if (!snapshot?.plan || snapshot.generation !== generation) {
    return;
  }
  if (
    tab?.id !== snapshot.plan.tab_id ||
    tab?.windowId !== snapshot.plan.window_id ||
    tab?.active !== true ||
    focusedWindowId !== snapshot.plan.window_id
  ) {
    sendContentFreeStatus("paused_background");
    return;
  }
  const now = Date.now();
  const remaining = snapshot.plan.minimum_interval_ms - (now - snapshot.lastSentAt);
  if (remaining > 0) {
    if (pendingTimer === null) {
      const expectedGeneration = generation;
      pendingTimer = setTimeout(() => {
        pendingTimer = null;
        if (generation === expectedGeneration) {
          void collectSelectedTab();
        }
      }, remaining);
    }
    return;
  }

  let visibleDocument = null;
  if (snapshot.plan.scope === "visible_text") {
    try {
      const results = await chrome.scripting.executeScript({
        target: { tabId: snapshot.plan.tab_id, frameIds: [0] },
        func: extractVisibleText,
        args: [snapshot.plan.maximum_payload_bytes],
      });
      visibleDocument = results.length === 1 ? results[0].result : null;
    } catch {
      sendContentFreeStatus("paused_protected");
      return;
    }
  }
  const sequence = snapshot.sequence + 1;
  let observation = await buildObservation(
    snapshot.plan,
    tab,
    focusedWindowId === snapshot.plan.window_id,
    visibleDocument,
    sequence,
    now,
  );
  visibleDocument = null;
  tab = null;
  if (!observation || active !== snapshot || snapshot.generation !== generation) {
    observation = null;
    return;
  }
  snapshot.port.postMessage(observation);
  observation = null;
  snapshot.sequence = sequence;
  snapshot.lastSentAt = now;
}

function extractVisibleText(maximumBytes) {
  if (
    document.visibilityState !== "visible" ||
    !["http:", "https:"].includes(location.protocol) ||
    !Number.isSafeInteger(maximumBytes) ||
    maximumBytes <= 0
  ) {
    return null;
  }
  const blocked = [
    "input",
    "textarea",
    "select",
    "option",
    "button",
    "script",
    "style",
    "noscript",
    "template",
    "[contenteditable]",
    "[aria-hidden='true']",
    "[hidden]",
    "[type='password']",
    "[autocomplete*='password' i]",
    "[data-stein-protected]",
  ].join(",");
  const encoder = new TextEncoder();
  const parts = [];
  let bytes = 0;
  const walker = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT);
  for (let node = walker.nextNode(); node; node = walker.nextNode()) {
    const parent = node.parentElement;
    if (!parent || parent.closest(blocked)) {
      continue;
    }
    const style = getComputedStyle(parent);
    if (style.display === "none" || style.visibility !== "visible" || Number(style.opacity) === 0) {
      continue;
    }
    const text = (node.textContent ?? "").replace(/\s+/gu, " ").trim();
    if (text === "") {
      continue;
    }
    const candidateBytes = encoder.encode(text).byteLength + (parts.length === 0 ? 0 : 1);
    if (bytes + candidateBytes > maximumBytes) {
      break;
    }
    parts.push(text);
    bytes += candidateBytes;
  }
  const value = parts.join(" ");
  parts.length = 0;
  return {
    text: value
      .replace(/\b[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}\b/gu, "[redacted-email]")
      .replace(/\b(password|passwd|secret|api_key|apikey|authorization|token)\s*[:=]\s*\S+/giu, "$1=[redacted]"),
    origin: location.origin,
    site: location.hostname,
  };
}

function sendContentFreeStatus(reason) {
  const snapshot = active;
  if (!snapshot?.plan) {
    return;
  }
  snapshot.port.postMessage({
    protocol_version: 1,
    kind: "source_status",
    authority_epoch: snapshot.plan.authority_epoch,
    selection_id: snapshot.plan.selection_id,
    state: "paused",
    reason,
  });
}

async function clearSelection() {
  generation += 1;
  if (pendingTimer !== null) {
    clearTimeout(pendingTimer);
    pendingTimer = null;
  }
  const previous = active;
  active = null;
  focusedWindowId = null;
  await chrome.storage.session.remove(SESSION_KEY);
  try {
    previous?.port.disconnect();
  } catch {
    // Disconnection is already the desired terminal state.
  }
  if (previous) {
    previous.offer = null;
    previous.plan = null;
  }
}

function randomHex(bytes) {
  if (!Number.isSafeInteger(bytes) || bytes <= 0 || bytes > 32) {
    return "";
  }
  const value = new Uint8Array(bytes);
  crypto.getRandomValues(value);
  return Array.from(value, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

async function randomProfileBinding() {
  const nonce = new Uint8Array(32);
  crypto.getRandomValues(nonce);
  const digest = await crypto.subtle.digest("SHA-256", nonce);
  nonce.fill(0);
  return Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, "0")).join("");
}
