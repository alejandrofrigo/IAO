const MAX_BODY_BYTES = 65536;
const ALLOWED_METHODS = new Set(["GET", "POST"]);
const FORWARDED_HEADERS = [
  "authorization",
  "content-type",
  "idempotency-key",
  "x-iao-device-proof",
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

function allowedPath(pathname) {
  if (pathname === "/health/live" || pathname === "/health/ready") return true;
  // The API remains the sole authorization and policy authority. The gateway
  // only forwards versioned API paths; it does not interpret or execute tasks.
  return pathname.startsWith("/v1/") &&
    !pathname.startsWith("/v1/gateway/") &&
    !pathname.startsWith("/v1/agent/");
}

export async function proxyApi(request, env) {
  const origin = configuredApiOrigin(env?.IAO_API_ORIGIN);
  if (!origin) return json(503, { error: "IAO_API_ORIGIN_NOT_CONFIGURED" });

  const incoming = new URL(request.url);
  if (!allowedPath(incoming.pathname)) return json(404, { error: "NOT_FOUND" });
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
