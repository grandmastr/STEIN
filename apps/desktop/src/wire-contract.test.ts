import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";
import {
  decodeClientMessageV1,
  decodePhase2RequestBodies,
  decodePhase2ResponseBodies,
  decodePhase2ViewEvents,
  decodeServerMessageV1,
} from "./wire-v1";

const CLIENT_FIXTURES = [
  "client-open-session.json",
  "client-open-session-v1-1.json",
  "client-create-goal.json",
  "client-get-snapshot.json",
  "client-get-runtime-status.json",
  "client-delay-echo.json",
  "client-shutdown.json",
  "client-start-focus-session.json",
  "client-cancel.json",
];

const SERVER_FIXTURES = [
  "server-session-opened.json",
  "server-session-opened-v1-1.json",
  "server-create-goal-response.json",
  "server-get-snapshot-response.json",
  "server-get-runtime-status-response.json",
  "server-delay-echo-response.json",
  "server-shutdown-response.json",
  "server-start-focus-session-response.json",
  "server-goal-event.json",
  "server-runtime-status-event.json",
  "server-focus-session-event.json",
  "server-error-response.json",
  "server-cancel-acknowledged.json",
  "server-event-gap.json",
  "server-fatal.json",
];

function fixture(name: string): string {
  const path = resolve(process.cwd(), "../../contracts/v1", name);
  return readFileSync(path, "utf8");
}

describe("Rust/TypeScript v1 golden wire contract", () => {
  for (const name of CLIENT_FIXTURES) {
    it(`decodes and re-encodes ${name}`, () => {
      const decoded = decodeClientMessageV1(fixture(name));
      expect(JSON.parse(JSON.stringify(decoded))).toEqual(JSON.parse(fixture(name)));
    });
  }

  for (const name of SERVER_FIXTURES) {
    it(`decodes and re-encodes ${name}`, () => {
      const decoded = decodeServerMessageV1(fixture(name));
      expect(JSON.parse(JSON.stringify(decoded))).toEqual(JSON.parse(fixture(name)));
    });
  }

  it("rejects unknown tagged message variants", () => {
    expect(() =>
      decodeClientMessageV1('{"message_type":"execute_tool","body":{}}'),
    ).toThrow("unsupported value");
  });

  it("rejects malformed nested request metadata", () => {
    const malformed = JSON.parse(fixture("client-create-goal.json")) as {
      body: { metadata: { sensitivity: unknown } };
    };
    malformed.body.metadata.sensitivity = "definitely_public";
    expect(() => decodeClientMessageV1(JSON.stringify(malformed))).toThrow(
      "message.body.metadata.sensitivity",
    );
  });

  it("round-trips every typed Phase 2 request body", () => {
    const source = fixture("phase2-request-bodies.json");
    expect(JSON.parse(JSON.stringify(decodePhase2RequestBodies(source)))).toEqual(JSON.parse(source));
  });

  it("round-trips every typed Phase 2 response body", () => {
    const source = fixture("phase2-response-bodies.json");
    expect(JSON.parse(JSON.stringify(decodePhase2ResponseBodies(source)))).toEqual(JSON.parse(source));
  });

  it("validates the additive content-free model request receipt", () => {
    const responses = decodePhase2ResponseBodies(fixture("phase2-response-bodies.json"));
    const focus = responses.find(
      (response) => response.response_type === "get_focus_session_view",
    );
    if (!focus || focus.response_type !== "get_focus_session_view") {
      throw new Error("fixture is missing get_focus_session_view");
    }
    const receipt = focus.payload.latest_model_request_receipt;
    expect(receipt).toBeDefined();
    expect(receipt?.focus_session_id).toBe(focus.payload.focus_session.focus_session_id);
    expect(receipt?.model_route_approval_id).toBe(
      focus.payload.focus_session.model_route_approval_id,
    );
    expect(receipt?.outcome).toBe("completed_strict_candidate");
    expect(Object.keys(receipt ?? {}).sort()).toEqual([
      "completed_at",
      "focus_session_id",
      "model_route_approval_id",
      "model_route_revision",
      "outcome",
      "request_id",
      "started_at",
    ]);

    const malformed = JSON.parse(fixture("phase2-response-bodies.json")) as Array<{
      response_type: string;
      payload: Record<string, unknown>;
    }>;
    const malformedFocus = malformed.find(
      (response) => response.response_type === "get_focus_session_view",
    );
    if (!malformedFocus) throw new Error("fixture is missing get_focus_session_view");
    const malformedReceipt = malformedFocus.payload.latest_model_request_receipt as Record<
      string,
      unknown
    >;
    malformedReceipt.outcome = "completed_with_provider_payload";
    expect(() => decodePhase2ResponseBodies(JSON.stringify(malformed))).toThrow(
      "latest_model_request_receipt.outcome",
    );
  });

  it("round-trips every typed Phase 2 view event", () => {
    const source = fixture("phase2-view-events.json");
    expect(JSON.parse(JSON.stringify(decodePhase2ViewEvents(source)))).toEqual(JSON.parse(source));
  });

  it("covers every additive protocol 1.2 desktop variant", () => {
    const requests = decodePhase2RequestBodies(fixture("phase2-request-bodies.json"));
    const responses = decodePhase2ResponseBodies(fixture("phase2-response-bodies.json"));
    const events = decodePhase2ViewEvents(fixture("phase2-view-events.json"));

    const v12Requests = [
      "delete_goal",
      "register_selected_resource",
      "remove_selected_resource",
      "update_user_preferences",
      "get_stein_identity",
      "get_user_preferences",
      "get_effective_policy",
      "get_selected_resources",
    ];
    expect(requests.map((request) => request.request_type)).toEqual(
      expect.arrayContaining(v12Requests),
    );
    expect(responses.map((response) => response.response_type)).toEqual(
      expect.arrayContaining(v12Requests),
    );
    expect(events.map((event) => event.event_type)).toEqual(
      expect.arrayContaining([
        "goal_deleted",
        "selected_resource_view_changed",
        "user_preferences_view_changed",
      ]),
    );
  });

  it("rejects an unknown Phase 2 permission scope", () => {
    const malformed = JSON.parse(fixture("phase2-request-bodies.json")) as Array<{
      request_type: string;
      payload: Record<string, unknown>;
    }>;
    const grant = malformed.find((item) => item.request_type === "grant_session_permission");
    if (!grant) throw new Error("fixture is missing grant_session_permission");
    grant.payload.scope = "observe.everything";
    expect(() => decodePhase2RequestBodies(JSON.stringify(malformed))).toThrow("scope");
  });
});
