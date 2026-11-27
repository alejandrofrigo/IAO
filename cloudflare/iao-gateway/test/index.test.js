import test from "node:test";
import assert from "node:assert/strict";
import worker from "../src/index.js";

const env = { IAO_GATEWAY_MODE: "disabled" };

test("liveness is available without claiming readiness", async () => {
  const live = await worker.fetch(new Request("https://example.test/health/live"), env);
  assert.equal(live.status, 200);
  assert.equal((await live.json()).status, "live");

  const ready = await worker.fetch(new Request("https://example.test/health/ready"), env);
  assert.equal(ready.status, 503);
  const body = await ready.json();
  assert.equal(body.status, "degraded");
  assert.equal(body.production_gates.privileged_commands, "disabled");
});

test("contract advertises no enabled commands", async () => {
  const response = await worker.fetch(new Request("https://example.test/v1/gateway/contract"), env);
  assert.equal(response.status, 200);
  const body = await response.json();
  assert.deepEqual(body.accepted_commands, []);
  assert.equal(body.task_submission, "disabled");
  assert.equal(body.agent_polling, "disabled");
});

test("task and agent routes fail closed", async () => {
  for (const path of ["/v1/tasks", "/v1/agent/poll", "/v1/agent/claim"]) {
    const response = await worker.fetch(new Request("https://example.test" + path, {
      method: path === "/v1/tasks" ? "POST" : "GET",
    }), env);
    assert.equal(response.status, 503);
    assert.equal((await response.json()).error, "GATEWAY_NOT_PROVISIONED");
  }
});

test("unknown paths are not routed", async () => {
  const response = await worker.fetch(new Request("https://example.test/admin"), env);
  assert.equal(response.status, 404);
});
