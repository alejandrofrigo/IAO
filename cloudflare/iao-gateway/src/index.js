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
    // The durable queue is intentionally not exposed until the API's
    // root+primary-device proof and agent lease protocol are integrated.
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
      return json(503, {
        status: "degraded",
        service: "iao-gateway",
        production_gates: {
          operator_root_and_device_verification: "not_integrated",
          termux_agent_authentication: "not_integrated",
          task_claim_and_lease_protocol: "not_integrated",
          result_signature_and_audit: "not_integrated",
          privileged_commands: "disabled",
        },
      });
    }

    if (request.method === "GET" && url.pathname === "/v1/gateway/contract") {
      return json(200, {
        protocol: "IAO-CLOUDFLARE-GATEWAY-V1",
        mode: "foundation_only",
        accepted_commands: [],
        task_submission: "disabled",
        agent_polling: "disabled",
        authority: "existing IAO root plus registered primary device; integration pending",
      });
    }

    if (url.pathname.startsWith("/v1/agent/") || url.pathname.startsWith("/v1/tasks")) {
      return json(503, {
        error: "GATEWAY_NOT_PROVISIONED",
        message: "No command or task endpoint is enabled until cryptographic authority integration is verified.",
      });
    }

    return json(404, { error: "NOT_FOUND" });
  },
};
