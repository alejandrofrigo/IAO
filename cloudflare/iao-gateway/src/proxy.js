const MAX_BODY_BYTES = 65536;
const ALLOWED_METHODS = new Set(["GET", "POST"]);
const FORWARDED_HEADERS = [
  "authorization",
  "content-type",
  "idempotency-key",
  "x-iao-device-proof",
  "x-iao-agent-id",
  "x-iao-agent-nonce",
  "x-iao-agent-timestamp",
  "x-iao-agent-signature",
];

function json(status, body) {
  return new Response(JSON.stringify(body), {
    status,
    headers: {
      "content-type": "application/json; charset=utf-8",
      "cache-control": "no-store",
      "x-content-type-options": "nosniff",
      "referrer-policy": "no-referrer",
    },
  });
}

export function configuredApiOrigin(value) {
  if (typeof value !== "string" || !value || value.length > 512) return null;
  try {
    const parsed = new URL(value);
    if (
      parsed.protocol !== "https:" ||
      !parsed.hostname ||
      parsed.username ||
      parsed.password ||
      parsed.port ||
      parsed.pathname !== "/" ||
      parsed.search ||
      parsed.hash ||
      parsed.hostname === "localhost" ||
      parsed.hostname.endsWith(".localhost") ||
      parsed.hostname.endsWith(".local") ||
      /^\d{1,3}(\.\d{1,3}){3}$/.test(parsed.hostname) ||
      parsed.hostname.includes(":")
    ) return null;
    return parsed.origin;
  } catch {
    return null;
  }
}

export function allowedRoute(method, pathname) {
  if (pathname === "/health/live" || pathname === "/health/ready") return method === "GET";

  // The gateway exposes only routes used by the public chat, signed primary
  // device workflows, task submission/status, and the read-only agent proof.
  // All other API routes remain private to the upstream service.
  if (pathname === "/v1/agent/challenge") return method === "POST";
  if (pathname === "/v1/agent/status") return method === "GET";

  const postRoutes = new Set([
    "/v1/public/session",
    "/v1/conversations",
    "/v1/chat",
    "/v1/operator/bootstrap/status",
    "/v1/operator/bootstrap",
    "/v1/operator/recovery/status",
    "/v1/operator/recovery/challenge",
    "/v1/operator/recovery/complete",
    "/v1/operator/login/challenge",
    "/v1/operator/login/complete",
    "/v1/operator/identity/revoke",
    "/v1/operator/device/bind",
    "/v1/operator/session/challenge",
    "/v1/operator/session/bind",
    "/v1/device/enroll",
    "/v1/device/challenge",
    "/v1/device/command",
    "/v1/tasks",
  ]);
  if (method === "POST" && postRoutes.has(pathname)) return true;

  if (method === "GET" && [
    "/v1/me",
    "/v1/operator/session/status",
  ].includes(pathname)) return true;

  if (method === "GET" &&
      /^\\/v1\\/conversations\\/[0-9a-f-]{36}\\/messages$/.test(pathname)) return true;
  if (method === "GET" && /^\\/v1\\/tasks\\/[0-9a-f-]{36}$/.test(pathname)) return true;
  return false;
}

export async function proxyApi(request, env) {
  const origin = configuredApiOrigin(env?.IAO_API_ORIGIN);
  if (!origin) return json(503, { error: "IAO_API_ORIGIN_NOT_CONFIGURED" });

  const incoming = new URL(request.url);
  if (!allowedRoute(request.method, incoming.pathname)) return json(404, { error: "NOT_FOUND" });
  if (!ALLOWED_METHODS.has(request.method)) {
    return json(405, { error: "METHOD_NOT_ALLOWED" });
  }

  const declaredLength = request.headers.get("content-length");
  if (declaredLength !== null) {
    const length = Number(declaredLength);
    if (!Number.isSafeInteger(length) || length < 0 || length > MAX_BODY_BYTES) {
      return json(413, { error: "PAYLOAD_TOO_LARGE" });
    }
  }

  let body;
  if (request.method === "POST") {
    body = await request.arrayBuffer();
    if (body.byteLength > MAX_BODY_BYTES) {
      return json(413, { error: "PAYLOAD_TOO_LARGE" });
    }
  }

  const headers = new Headers();
  for (const name of FORWARDED_HEADERS) {
    const value = request.headers.get(name);
    if (value !== null) headers.set(name, value);
  }

  const target = new URL(origin);
  target.pathname = incoming.pathname;
  target.search = incoming.search;

  let upstream;
  try {
    upstream = await fetch(target, {
      method: request.method,
      headers,
      body: request.method === "POST" ? body : undefined,
      redirect: "manual",
      signal: request.signal,
    });
  } catch {
    return json(503, { error: "IAO_API_UNAVAILABLE" });
  }

  if (upstream.status >= 300 && upstream.status < 400) {
    return json(502, { error: "IAO_API_REDIRECT_BLOCKED" });
  }

  const responseHeaders = new Headers({
    "cache-control": "no-store",
    "x-content-type-options": "nosniff",
    "referrer-policy": "no-referrer",
  });
  const contentType = upstream.headers.get("content-type");
  if (contentType) responseHeaders.set("content-type", contentType);

  return new Response(upstream.body, {
    status: upstream.status,
    headers: responseHeaders,
  });
}
