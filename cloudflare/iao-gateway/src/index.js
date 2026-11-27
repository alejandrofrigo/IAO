import { proxyApi, allowedRoute } from "./proxy.js";

const JSON_HEADERS = {
  "content-type": "application/json; charset=utf-8",
  "cache-control": "no-store",
  "x-content-type-options": "nosniff",
  "referrer-policy": "no-referrer",
};
const CORS_ALLOWED_HEADERS = new Set([
  "authorization",
  "content-type",
  "idempotency-key",
  "x-iao-device-proof",
  "x-iao-agent-id",
  "x-iao-agent-nonce",
  "x-iao-agent-timestamp",
  "x-iao-agent-signature",
]);

function json(status, body) {
  return new Response(JSON.stringify(body), {
    status,
    headers: JSON_HEADERS,
  });
}

function configuredWebOrigins(value) {
  const result = new Set();
  if (typeof value !== "string" || !value.trim()) return result;
  for (const item of value.split(",")) {
    const candidate = item.trim();
    if (!candidate || candidate.length > 512) continue;
    try {
      const parsed = new URL(candidate);
      const loopback = parsed.hostname === "localhost" ||
        parsed.hostname === "127.0.0.1" || parsed.hostname === "[::1]";
      if (
        parsed.origin !== candidate ||
        (parsed.protocol !== "https:" &&
          !(parsed.protocol === "http:" && loopback)) ||
        parsed.username || parsed.password || parsed.pathname !== "/" ||
        parsed.search || parsed.hash
      ) continue;
      result.add(parsed.origin);
    } catch {
      // Invalid origins are ignored; no wildcard fallback is permitted.
    }
  }
  return result;
}

function withCors(response, origin) {
  if (!origin) return response;
  const headers = new Headers(response.headers);
  headers.set("access-control-allow-origin", origin);
  const vary = headers.get("vary");
  headers.set("vary", vary ? vary + ", Origin" : "Origin");
  return new Response(response.body, {
    status: response.status,
    statusText: response.statusText,
    headers,
  });
}

function preflight(request, env, origin) {
  if (!origin) return json(400, { error: "CORS_ORIGIN_REQUIRED" });
  const url = new URL(request.url);
  const method = (request.headers.get("access-control-request-method") || "").toUpperCase();
  const routeAllowed = (
    (url.pathname === "/v1/gateway/contract" && method === "GET") ||
    allowedRoute(method, url.pathname)
  );
  const requestedHeaders = (request.headers.get("access-control-request-headers") || "")
    .split(",").map(value => value.trim().toLowerCase()).filter(Boolean);
  if (
    !routeAllowed ||
    !["GET", "POST"].includes(method) ||
    requestedHeaders.some(name => !CORS_ALLOWED_HEADERS.has(name))
  ) {
    return json(403, { error: "CORS_PREFLIGHT_BLOCKED" });
  }
  return withCors(new Response(null, {
    status: 204,
    headers: {
      "access-control-allow-methods": "GET, POST, OPTIONS",
      "access-control-allow-headers": Array.from(CORS_ALLOWED_HEADERS).join(", "),
      "access-control-max-age": "600",
      "cache-control": "no-store",
    },
  }), origin);
}

export class TaskBroker {
  constructor(ctx, env) {
    this.ctx = ctx;
    this.env = env;
  }

  async fetch() {
    // The DO remains deliberately disabled. The Python API's SQLite task
    // store is the current source of truth; a second queue would split leases.
    return json(503, { status: "disabled", error: "BROKER_AUTHORITY_NOT_INTEGRATED" });
  }
}

async function route(request, env) {
  const url = new URL(request.url);

  if (request.method === "GET" && url.pathname === "/health/live") {
    return json(200, { status: "live", service: "iao-gateway" });
  }

  if (request.method === "GET" && url.pathname === "/health/ready") {
    const upstream = await proxyApi(request, env);
    if (!upstream.ok) {
      return json(503, {
        status: "degraded",
        service: "iao-gateway",
        upstream_status: upstream.status,
        privileged_commands: "disabled",
        agent_polling: "disabled",
      });
    }
    let payload;
    try { payload = await upstream.clone().json(); } catch { payload = {}; }
    if (payload.status !== "normal") {
      return json(503, {
        status: "degraded",
        service: "iao-gateway",
        upstream_status: upstream.status,
        upstream_readiness: payload.status || "unknown",
        privileged_commands: "disabled",
        agent_polling: "disabled",
      });
    }
    return upstream;
  }

  if (request.method === "GET" && url.pathname === "/v1/gateway/contract") {
    return json(200, {
      protocol: "IAO-CLOUDFLARE-GATEWAY-V1",
      mode: "fixed_origin_api_proxy",
      task_submission: "forwarded_to_IAO_API_authorization_required",
      agent_polling: "disabled",
      agent_status: "signed_read_only_forwarding_only",
      privileged_commands: "disabled",
      durable_object_queue: "disabled; IAO API task store remains authoritative",
      authority: "existing IAO root, operator session and registered primary device",
    });
  }

  if (url.pathname.startsWith("/v1/agent/")) {
    if (
      (url.pathname === "/v1/agent/challenge" && request.method === "POST") ||
      (url.pathname === "/v1/agent/status" && request.method === "GET")
    ) {
      return proxyApi(request, env);
    }
    return json(503, {
      error: "AGENT_TASK_PROTOCOL_DISABLED",
      message: "Only signed challenge and read-only status requests may be forwarded.",
    });
  }

  if (url.pathname.startsWith("/v1/")) {
    return proxyApi(request, env);
  }

  return json(404, { error: "NOT_FOUND" });
}

export default {
  async fetch(request, env) {
    const origin = request.headers.get("origin");
    const allowedOrigins = configuredWebOrigins(env?.IAO_WEB_ORIGINS);
    if (origin && !allowedOrigins.has(origin)) {
      return json(403, { error: "CORS_ORIGIN_NOT_ALLOWED" });
    }
    if (request.method === "OPTIONS") {
      return preflight(request, env, origin);
    }
    return withCors(await route(request, env), origin);
  },
};
