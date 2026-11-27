import test from "node:test";
import assert from "node:assert/strict";
import worker from "../src/index.js";

const disabledEnv = {};

test("liveness is available without claiming readiness", async () => {
  const live = await worker.fetch(new Request("https://example.test/health/live"), disabledEnv);
  assert.equal(live.status, 200);
  assert.equal((await live.json()).status, "live");

  const ready = await worker.fetch(new Request("https://example.test/health/ready"), disabledEnv);
  assert.equal(ready.status, 503);
  assert.equal((await ready.json()).status, "degraded");
});

test("contract states the API proxy boundary and keeps agent polling disabled", async () => {
  const response = await worker.fetch(new Request("https://example.test/v1/gateway/contract"), disabledEnv);
  assert.equal(response.status, 200);
  const body = await response.json();
  assert.equal(body.mode, "disabled");
  assert.equal(body.agent_polling, "disabled");
  assert.equal(body.agent_status, "signed_read_only_forwarding_only");
  assert.equal(body.privileged_commands, "disabled");
});

test("gateway mode remains disabled even when an API origin is present", async () => {
  const response = await worker.fetch(new Request("https://gateway.test/v1/chat", {
    method: "POST",
    body: "{}",
  }), { IAO_API_ORIGIN: "https://api.example.net" });
  assert.equal(response.status, 503);
  assert.equal((await response.json()).error, "GATEWAY_DISABLED");
});

test("CORS preflight requires an exact configured web origin and allowed API route", async () => {
  const env = { IAO_GATEWAY_MODE: "enabled", IAO_WEB_ORIGINS: "https://chat.example.net" };
  const accepted = await worker.fetch(new Request("https://gateway.test/v1/public/session", {
    method: "OPTIONS",
    headers: {
      origin: "https://chat.example.net",
      "access-control-request-method": "POST",
      "access-control-request-headers": "authorization,content-type",
    },
  }), env);
  assert.equal(accepted.status, 204);
  assert.equal(accepted.headers.get("access-control-allow-origin"), "https://chat.example.net");
  assert.match(accepted.headers.get("access-control-allow-headers"), /authorization/i);

  const unknownOrigin = await worker.fetch(new Request("https://gateway.test/v1/public/session", {
    method: "OPTIONS",
    headers: {
      origin: "https://attacker.example",
      "access-control-request-method": "POST",
    },
  }), env);
  assert.equal(unknownOrigin.status, 403);
  assert.equal((await unknownOrigin.json()).error, "CORS_ORIGIN_NOT_ALLOWED");

  const blockedHeader = await worker.fetch(new Request("https://gateway.test/v1/public/session", {
    method: "OPTIONS",
    headers: {
      origin: "https://chat.example.net",
      "access-control-request-method": "POST",
      "access-control-request-headers": "x-untrusted-header",
    },
  }), env);
  assert.equal(blockedHeader.status, 403);
  assert.equal((await blockedHeader.json()).error, "CORS_PREFLIGHT_BLOCKED");
});

test("allowed browser API responses include the exact CORS origin", async () => {
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async () => new Response(JSON.stringify({ access_token: "opaque" }), {
    status: 201,
    headers: { "content-type": "application/json" },
  });
  try {
    const response = await worker.fetch(new Request("https://gateway.test/v1/public/session", {
      method: "POST",
      headers: {
        origin: "https://chat.example.net",
        "content-type": "application/json",
      },
      body: "{}",
    }), {
      IAO_GATEWAY_MODE: "enabled",
      IAO_API_ORIGIN: "https://api.example.net",
      IAO_WEB_ORIGINS: "https://chat.example.net",
    });
    assert.equal(response.status, 201);
    assert.equal(response.headers.get("access-control-allow-origin"), "https://chat.example.net");
    assert.equal(response.headers.get("vary"), "Origin");
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("API routes fail closed when no fixed origin is configured", async () => {
  const response = await worker.fetch(new Request("https://example.test/v1/tasks", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ goal: "diagnostic" }),
  }), { IAO_GATEWAY_MODE: "enabled" });
  assert.equal(response.status, 503);
  assert.equal((await response.json()).error, "IAO_API_ORIGIN_NOT_CONFIGURED");
});

test("fixed-origin proxy forwards signed API request without cookies or client identity headers", async () => {
  const originalFetch = globalThis.fetch;
  let captured;
  globalThis.fetch = async (url, init) => {
    captured = { url: String(url), init };
    return new Response(JSON.stringify({ accepted: true }), {
      status: 202,
      headers: { "content-type": "application/json" },
    });
  };
  try {
    const body = JSON.stringify({ goal: "read-only status", capability: "system.status", input: {} });
    const response = await worker.fetch(new Request("https://gateway.test/v1/tasks?source=chat", {
      method: "POST",
      headers: {
        "content-type": "application/json",
        authorization: "Bearer opaque-session",
        "x-iao-device-proof": "signed-proof",
        "x-iao-agent-id": "must-not-forward-on-task-route",
        "idempotency-key": "task-001",
        cookie: "must-not-forward",
        "x-forwarded-for": "198.51.100.4",
      },
      body,
    }), { IAO_GATEWAY_MODE: "enabled",
      IAO_API_ORIGIN: "https://api.example.net" });
    assert.equal(response.status, 202);
    assert.deepEqual(await response.json(), { accepted: true });
    assert.equal(captured.url, "https://api.example.net/v1/tasks?source=chat");
    assert.equal(captured.init.method, "POST");
    assert.equal(captured.init.headers.get("authorization"), "Bearer opaque-session");
    assert.equal(captured.init.headers.get("x-iao-device-proof"), "signed-proof");
    assert.equal(captured.init.headers.get("idempotency-key"), "task-001");
    assert.equal(captured.init.headers.get("x-iao-agent-id"), null);
    assert.equal(captured.init.headers.get("cookie"), null);
    assert.equal(captured.init.headers.get("x-forwarded-for"), null);
    assert.equal(new TextDecoder().decode(captured.init.body), body);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("signed read-only agent challenge and status routes forward exact protocol headers", async () => {
  const originalFetch = globalThis.fetch;
  const captured = [];
  globalThis.fetch = async (url, init) => {
    captured.push({ url: String(url), init });
    return new Response(JSON.stringify({ accepted: true }), {
      status: 200,
      headers: { "content-type": "application/json" },
    });
  };
  try {
    const origin = "https://api.example.net";
    const agentId = "a".repeat(32);
    const challengeBody = JSON.stringify({ agent_id: agentId });
    const challenge = await worker.fetch(new Request("https://gateway.test/v1/agent/challenge", {
      method: "POST",
      headers: { "content-type": "application/json", cookie: "never-forward" },
      body: challengeBody,
    }), { IAO_GATEWAY_MODE: "enabled",
      IAO_API_ORIGIN: origin });
    assert.equal(challenge.status, 200);

    const status = await worker.fetch(new Request("https://gateway.test/v1/agent/status", {
      method: "GET",
      headers: {
        "x-iao-agent-id": agentId,
        "x-iao-agent-nonce": "b".repeat(64),
        "x-iao-agent-timestamp": "1795750000",
        "x-iao-agent-signature": "c".repeat(88),
        cookie: "never-forward",
        "x-forwarded-for": "198.51.100.8",
      },
    }), { IAO_GATEWAY_MODE: "enabled",
      IAO_API_ORIGIN: origin });
    assert.equal(status.status, 200);

    assert.equal(captured.length, 2);
    assert.equal(captured[0].url, origin + "/v1/agent/challenge");
    assert.equal(captured[0].init.method, "POST");
    assert.equal(new TextDecoder().decode(captured[0].init.body), challengeBody);
    assert.equal(captured[0].init.headers.get("cookie"), null);

    assert.equal(captured[1].url, origin + "/v1/agent/status");
    assert.equal(captured[1].init.method, "GET");
    assert.equal(captured[1].init.headers.get("x-iao-agent-id"), agentId);
    assert.equal(captured[1].init.headers.get("x-iao-agent-nonce"), "b".repeat(64));
    assert.equal(captured[1].init.headers.get("x-iao-agent-timestamp"), "1795750000");
    assert.equal(captured[1].init.headers.get("x-iao-agent-signature"), "c".repeat(88));
    assert.equal(captured[1].init.headers.get("cookie"), null);
    assert.equal(captured[1].init.headers.get("x-forwarded-for"), null);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("invalid origins, redirects, oversized bodies and unsupported agent routes fail closed", async () => {
  for (const origin of [
    "http://api.example.net",
    "https://localhost",
    "https://127.0.0.1",
    "https://api.example.net/path",
    "https://user:pass@api.example.net",
  ]) {
    const response = await worker.fetch(new Request("https://gateway.test/v1/chat", { method: "POST", body: "{}" }), {
      IAO_GATEWAY_MODE: "enabled",
      IAO_API_ORIGIN: origin,
    });
    assert.equal(response.status, 503, origin);
  }

  const agent = await worker.fetch(new Request("https://gateway.test/v1/agent/poll"), {
    IAO_GATEWAY_MODE: "enabled",
      IAO_API_ORIGIN: "https://api.example.net",
  });
  assert.equal(agent.status, 503);
  assert.equal((await agent.json()).error, "AGENT_TASK_PROTOCOL_DISABLED");

  const unknown = await worker.fetch(new Request("https://gateway.test/admin"), disabledEnv);
  assert.equal(unknown.status, 404);

  const oversized = await worker.fetch(new Request("https://gateway.test/v1/chat", {
    method: "POST",
    body: "x".repeat(65537),
  }), { IAO_GATEWAY_MODE: "enabled",
      IAO_API_ORIGIN: "https://api.example.net" });
  assert.equal(oversized.status, 413);
});

test("unlisted sensitive API routes are not forwarded", async () => {
  const originalFetch = globalThis.fetch;
  let fetchCalls = 0;
  globalThis.fetch = async () => {
    fetchCalls += 1;
    return new Response("unexpected", { status: 200 });
  };
  try {
    const blocked = [
      ["POST", "/v1/federation/internet"],
      ["GET", "/v1/audit/events"],
      ["POST", "/v1/memory"],
      ["POST", "/v1/operator/unlisted-control"],
      ["POST", "/v1/device/unlisted-control"],
    ];
    for (const [method, path] of blocked) {
      const response = await worker.fetch(new Request("https://gateway.test" + path, {
        method,
        ...(method === "POST" ? { body: "{}" } : {}),
      }), { IAO_GATEWAY_MODE: "enabled",
      IAO_API_ORIGIN: "https://api.example.net" });
      assert.equal(response.status, 404, path);
    }
    const delegation = await worker.fetch(
      new Request("https://gateway.test/v1/agent/delegation", {
        method: "POST", body: "{}",
      }),
      { IAO_GATEWAY_MODE: "enabled",
      IAO_API_ORIGIN: "https://api.example.net" },
    );
    assert.equal(delegation.status, 503);
    assert.equal((await delegation.json()).error, "AGENT_TASK_PROTOCOL_DISABLED");
    assert.equal(fetchCalls, 0);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("upstream redirects are never followed", async () => {
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async () => new Response(null, {
    status: 302,
    headers: { location: "https://untrusted.example/collect" },
  });
  try {
    const response = await worker.fetch(new Request("https://gateway.test/v1/chat", { method: "POST", body: "{}" }), {
      IAO_GATEWAY_MODE: "enabled",
      IAO_API_ORIGIN: "https://api.example.net",
    });
    assert.equal(response.status, 502);
    assert.equal((await response.json()).error, "IAO_API_REDIRECT_BLOCKED");
  } finally {
    globalThis.fetch = originalFetch;
  }
});
