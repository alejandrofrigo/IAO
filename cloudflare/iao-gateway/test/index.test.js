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
  assert.equal(body.mode, "fixed_origin_api_proxy");
  assert.equal(body.agent_polling, "disabled");
  assert.equal(body.privileged_commands, "disabled");
});

test("API routes fail closed when no fixed origin is configured", async () => {
  const response = await worker.fetch(new Request("https://example.test/v1/tasks", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ goal: "diagnostic" }),
  }), disabledEnv);
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
        "idempotency-key": "task-001",
        cookie: "must-not-forward",
        "x-forwarded-for": "198.51.100.4",
      },
      body,
    }), { IAO_API_ORIGIN: "https://api.example.net" });
    assert.equal(response.status, 202);
    assert.deepEqual(await response.json(), { accepted: true });
    assert.equal(captured.url, "https://api.example.net/v1/tasks?source=chat");
    assert.equal(captured.init.method, "POST");
    assert.equal(captured.init.headers.get("authorization"), "Bearer opaque-session");
    assert.equal(captured.init.headers.get("x-iao-device-proof"), "signed-proof");
    assert.equal(captured.init.headers.get("idempotency-key"), "task-001");
    assert.equal(captured.init.headers.get("cookie"), null);
    assert.equal(captured.init.headers.get("x-forwarded-for"), null);
    assert.equal(new TextDecoder().decode(captured.init.body), body);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("invalid origins, redirects, oversized bodies and agent routes fail closed", async () => {
  for (const origin of [
    "http://api.example.net",
    "https://localhost",
    "https://127.0.0.1",
    "https://api.example.net/path",
    "https://user:pass@api.example.net",
  ]) {
    const response = await worker.fetch(new Request("https://gateway.test/v1/chat", { method: "POST", body: "{}" }), {
      IAO_API_ORIGIN: origin,
    });
    assert.equal(response.status, 503, origin);
  }

  const agent = await worker.fetch(new Request("https://gateway.test/v1/agent/poll"), {
    IAO_API_ORIGIN: "https://api.example.net",
  });
  assert.equal(agent.status, 503);
  assert.equal((await agent.json()).error, "AGENT_PROTOCOL_NOT_INTEGRATED");

  const unknown = await worker.fetch(new Request("https://gateway.test/admin"), disabledEnv);
  assert.equal(unknown.status, 404);

  const oversized = await worker.fetch(new Request("https://gateway.test/v1/chat", {
    method: "POST",
    body: "x".repeat(65537),
  }), { IAO_API_ORIGIN: "https://api.example.net" });
  assert.equal(oversized.status, 413);
});

test("upstream redirects are never followed", async () => {
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async () => new Response(null, {
    status: 302,
    headers: { location: "https://untrusted.example/collect" },
  });
  try {
    const response = await worker.fetch(new Request("https://gateway.test/v1/chat", { method: "POST", body: "{}" }), {
      IAO_API_ORIGIN: "https://api.example.net",
    });
    assert.equal(response.status, 502);
    assert.equal((await response.json()).error, "IAO_API_REDIRECT_BLOCKED");
  } finally {
    globalThis.fetch = originalFetch;
  }
});
