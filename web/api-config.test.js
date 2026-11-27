const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const vm = require("node:vm");

const source = fs.readFileSync(__dirname + "/api-config.js", "utf8");

function load(overrides = {}, meta = null) {
  const window = {
    ...overrides,
    document: {
      querySelector(selector) {
        assert.equal(selector, 'meta[name="iao-api-base"]');
        return meta;
      },
    },
  };
  vm.runInNewContext(source, { window, URL });
  return window;
}

test("blocks API calls when no origin is configured", () => {
  const api = load();
  assert.equal(api.IAO_API_CONFIG_STATUS, "blocked");
  assert.throws(() => api.iaoApiUrl("/v1/tasks"), /API_BASE_NOT_CONFIGURED/);
});

test("uses an explicitly configured HTTPS origin", () => {
  const api = load({ IAO_API_BASE_OVERRIDE: "https://api.example.org/" });
  assert.equal(api.IAO_API_BASE, "https://api.example.org");
  assert.equal(api.IAO_API_CONFIG_STATUS, "configured");
  assert.equal(api.iaoApiUrl("/v1/tasks"), "https://api.example.org/v1/tasks");
});

test("accepts the deployment meta tag when no override exists", () => {
  const api = load({}, { content: "https://gateway.example.org" });
  assert.equal(api.iaoApiUrl("/health/ready"), "https://gateway.example.org/health/ready");
});

test("rejects insecure or ambiguous API origins", () => {
  for (const value of [
    "http://api.example.org",
    "https://user:pass@example.org",
    "https://api.example.org/path",
    "https://api.example.org/?token=x",
    "https://api.example.org/#fragment",
    "https://api.example.org:8443",
  ]) {
    const api = load({ IAO_API_BASE_OVERRIDE: value });
    assert.equal(api.IAO_API_CONFIG_STATUS, "blocked", value);
    assert.throws(() => api.iaoApiUrl("/v1/tasks"), /INVALID_API_BASE/, value);
  }
});

test("allows HTTP only for local development loopback", () => {
  const api = load({ IAO_API_BASE_OVERRIDE: "http://127.0.0.1:8080" });
  assert.equal(api.iaoApiUrl("/v1/tasks"), "http://127.0.0.1:8080/v1/tasks");
});

test("rejects paths outside the API surface and path traversal", () => {
  const api = load({ IAO_API_BASE_OVERRIDE: "https://api.example.org" });
  for (const path of [
    "https://attacker.example/",
    "//attacker.example/v1/tasks",
    "/admin/secrets",
    "/v1/../admin",
    "/v1//tasks",
    "/health/..//admin",
  ]) {
    assert.throws(() => api.iaoApiUrl(path), /INVALID_API_PATH/, path);
  }
});

test("preserves safe API query strings without changing origin", () => {
  const api = load({ IAO_API_BASE_OVERRIDE: "https://api.example.org" });
  assert.equal(
    api.iaoApiUrl("/v1/tasks?limit=5"),
    "https://api.example.org/v1/tasks?limit=5",
  );
});
