import { proxyApi } from "./proxy.js";

const JSON_HEADERS = {
  "content-type": "application/json; charset=utf-8",
  "cache-control": "no-store",
  "x-content-type-options": "nosniff",
  "referrer-policy": "no-referrer",
};

function json(status, body) {
  return new Response(JSON.stringify(body), {
    status,
    headers: JSON_HEADERS,
  });
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

export default {
  async fetch(request, env) {
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
  },
};
