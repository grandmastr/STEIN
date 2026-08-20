const MAXIMUM_NATIVE_MESSAGE_BYTES = 64 * 1024;
const MAXIMUM_SELECTION_COMPONENT_BYTES = 4 * 1024;
const MINIMUM_INTERVAL_MILLISECONDS = 1_000;
const MAXIMUM_INTERVAL_MILLISECONDS = 60_000;
const HEX_32 = /^[0-9a-f]{32}$/u;
const HEX_64 = /^[0-9a-f]{64}$/u;

export function isExactReleaseExtensionId(actual, expected) {
  return /^[a-p]{32}$/u.test(expected) && actual === expected;
}

export function standardWebLocation(rawUrl) {
  if (typeof rawUrl !== "string" || rawUrl.length > MAXIMUM_SELECTION_COMPONENT_BYTES) {
    return null;
  }
  let parsed;
  try {
    parsed = new URL(rawUrl);
  } catch {
    return null;
  }
  if (
    !["http:", "https:"].includes(parsed.protocol) ||
    parsed.username !== "" ||
    parsed.password !== "" ||
    parsed.hostname === ""
  ) {
    return null;
  }
  return {
    origin: parsed.origin,
    site: parsed.hostname,
    path: parsed.pathname,
    query: parsed.search.startsWith("?") ? parsed.search.slice(1) : "",
    fragment: parsed.hash.startsWith("#") ? parsed.hash.slice(1) : "",
  };
}

export async function buildSelectionOffer(tab, runtimeExtensionId, expectedExtensionId) {
  if (
    !isExactReleaseExtensionId(runtimeExtensionId, expectedExtensionId) ||
    !Number.isInteger(tab?.id) ||
    tab.id <= 0 ||
    !Number.isInteger(tab?.windowId) ||
    tab.windowId <= 0 ||
    tab.active !== true ||
    tab.incognito === true
  ) {
    return null;
  }
  const location = standardWebLocation(tab.url);
  if (!location) {
    return null;
  }
  return {
    protocol_version: 1,
    kind: "selection_offer",
    extension_id: runtimeExtensionId,
    tab_id: tab.id,
    window_id: tab.windowId,
    active: true,
    incognito: false,
    page_kind: "standard_web_page",
    site: location.site,
    origin: location.origin,
    site_sha256: await sha256Hex(location.site),
    origin_sha256: await sha256Hex(location.origin),
  };
}

export function validateCapturePlan(plan, offer, runtimeExtensionId, expectedExtensionId) {
  if (
    !isExactReleaseExtensionId(runtimeExtensionId, expectedExtensionId) ||
    offer?.protocol_version !== 1 ||
    offer?.kind !== "selection_offer" ||
    offer?.extension_id !== expectedExtensionId ||
    offer?.active !== true ||
    offer?.incognito !== false ||
    offer?.page_kind !== "standard_web_page" ||
    plan?.protocol_version !== 1 ||
    plan?.kind !== "capture_plan" ||
    plan?.extension_id !== expectedExtensionId ||
    !["location", "visible_text"].includes(plan?.scope) ||
    !Number.isSafeInteger(plan?.authority_epoch) ||
    plan.authority_epoch <= 0 ||
    !HEX_64.test(plan?.profile_binding_sha256 ?? "") ||
    !HEX_32.test(plan?.browser_session_id ?? "") ||
    !HEX_32.test(plan?.selection_id ?? "") ||
    plan?.tab_id !== offer?.tab_id ||
    plan?.window_id !== offer?.window_id ||
    plan?.site_sha256 !== offer?.site_sha256 ||
    plan?.origin_sha256 !== offer?.origin_sha256 ||
    !Number.isSafeInteger(plan?.maximum_payload_bytes) ||
    plan.maximum_payload_bytes <= 0 ||
    plan.maximum_payload_bytes > 16 * 1024 ||
    !Number.isSafeInteger(plan?.minimum_interval_ms) ||
    plan.minimum_interval_ms < MINIMUM_INTERVAL_MILLISECONDS ||
    plan.minimum_interval_ms > MAXIMUM_INTERVAL_MILLISECONDS
  ) {
    return null;
  }
  const granularity = plan.granularity;
  if (
    typeof granularity?.origin !== "boolean" ||
    typeof granularity?.path !== "boolean" ||
    typeof granularity?.query !== "boolean" ||
    typeof granularity?.fragment !== "boolean"
  ) {
    return null;
  }
  if (
    plan.scope === "location" &&
    !granularity.origin &&
    !granularity.path &&
    !granularity.query &&
    !granularity.fragment
  ) {
    return null;
  }
  if (
    plan.scope === "visible_text" &&
    (granularity.origin || granularity.path || granularity.query || granularity.fragment)
  ) {
    return null;
  }
  return Object.freeze({
    protocol_version: 1,
    scope: plan.scope,
    extension_id: plan.extension_id,
    authority_epoch: plan.authority_epoch,
    profile_binding_sha256: plan.profile_binding_sha256,
    browser_session_id: plan.browser_session_id,
    selection_id: plan.selection_id,
    tab_id: plan.tab_id,
    window_id: plan.window_id,
    site_sha256: plan.site_sha256,
    origin_sha256: plan.origin_sha256,
    granularity: Object.freeze({ ...granularity }),
    maximum_payload_bytes: plan.maximum_payload_bytes,
    minimum_interval_ms: plan.minimum_interval_ms,
  });
}

export async function buildObservation(plan, tab, windowFocused, visibleText, sequence, now) {
  if (
    !plan ||
    !Number.isSafeInteger(sequence) ||
    sequence <= 0 ||
    !Number.isSafeInteger(now) ||
    tab?.id !== plan.tab_id ||
    tab?.windowId !== plan.window_id ||
    tab?.active !== true ||
    windowFocused !== true ||
    tab?.incognito === true
  ) {
    return null;
  }
  const current = standardWebLocation(tab.url);
  if (!current) {
    return null;
  }
  const siteDigest = await sha256Hex(current.site);
  const originDigest = await sha256Hex(current.origin);
  if (siteDigest !== plan.site_sha256 || originDigest !== plan.origin_sha256) {
    return null;
  }

  const envelope = {
    protocol_version: 1,
    authority_epoch: plan.authority_epoch,
    sequence,
    profile_binding_sha256: plan.profile_binding_sha256,
    browser_session_id: plan.browser_session_id,
    selection_id: plan.selection_id,
    tab_id: plan.tab_id,
    window_id: plan.window_id,
    active: true,
    window_focused: true,
    incognito: false,
    top_frame: true,
    page_kind: "standard_web_page",
    site_sha256: siteDigest,
    origin_sha256: originDigest,
    location: null,
    visible_text: null,
    observed_at_unix_ms: now,
  };
  if (plan.scope === "location") {
    envelope.location = {
      origin: plan.granularity.origin ? current.origin : null,
      path: plan.granularity.path ? current.path : null,
      query: plan.granularity.query && current.query !== "" ? current.query : null,
      fragment: plan.granularity.fragment && current.fragment !== "" ? current.fragment : null,
    };
  } else if (plan.scope === "visible_text") {
    envelope.visible_text = boundUtf8(localRedact(visibleText), plan.maximum_payload_bytes);
    if (envelope.visible_text === "") {
      return null;
    }
  } else {
    return null;
  }
  return encodedBytes(envelope) <= MAXIMUM_NATIVE_MESSAGE_BYTES ? envelope : null;
}

export function localRedact(value) {
  if (typeof value !== "string") {
    return "";
  }
  const tokens = value.replace(/[\u0000-\u001f\u007f]/gu, " ").split(/\s+/u);
  const output = [];
  let redactNext = false;
  for (const token of tokens) {
    if (token === "") {
      continue;
    }
    const lower = token.toLowerCase();
    const label = /^(password|passwd|secret|api_key|apikey|authorization|bearer|token)[:=]?$/u.test(lower);
    const inline = /^(password|passwd|secret|api_key|apikey|authorization|token)[:=]/u.test(lower);
    if (redactNext || inline) {
      output.push("[redacted]");
    } else if (token.includes("@")) {
      output.push("[redacted-email]");
    } else if (token.length >= 32 && token.split(".").length === 3) {
      output.push("[redacted-token]");
    } else {
      output.push(token);
    }
    redactNext = label;
  }
  return output.join(" ");
}

export function boundUtf8(value, maximumBytes) {
  if (typeof value !== "string" || !Number.isSafeInteger(maximumBytes) || maximumBytes <= 0) {
    return "";
  }
  const encoder = new TextEncoder();
  if (encoder.encode(value).byteLength <= maximumBytes) {
    return value;
  }
  let output = "";
  for (const scalar of value) {
    const candidate = output + scalar;
    if (encoder.encode(candidate).byteLength > maximumBytes) {
      break;
    }
    output = candidate;
  }
  return output.trimEnd();
}

export function encodedBytes(value) {
  return new TextEncoder().encode(JSON.stringify(value)).byteLength;
}

async function sha256Hex(value) {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value));
  return Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, "0")).join("");
}
