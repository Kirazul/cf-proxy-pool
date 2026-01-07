/**
 * CF Proxy Pool - Cloudflare Worker Proxy Pool Manager
 * 
 * Deploys and manages a pool of proxy workers for request routing
 * with automatic IP rotation via X-Forwarded-For spoofing.
 * 
 * Environment variables (set via `wrangler secret put`):
 * - CF_API_TOKEN: Cloudflare API token with Workers edit permission
 * - CF_ACCOUNT_ID: Your Cloudflare account ID
 * - API_KEY: Secret key for admin endpoints (optional)
 * 
 * @see https://github.com/Kirazul/cf-proxy-pool
 */

const PROXY_WORKER_SCRIPT = `addEventListener('fetch', e => e.respondWith(handleRequest(e.request)));

async function handleRequest(request) {
  const url = new URL(request.url);
  
  if (request.method === 'OPTIONS') {
    return new Response(null, { status: 204, headers: corsHeaders() });
  }
  
  if (url.pathname === '/ip') {
    const r = await fetch('https://api.ipify.org?format=json');
    const d = await r.json();
    return new Response(JSON.stringify(d), { headers: { 'Content-Type': 'application/json', ...corsHeaders() }});
  }
  
  const targetUrl = url.searchParams.get('url') || request.headers.get('X-Target-URL');
  if (!targetUrl) {
    return new Response(JSON.stringify({ error: 'No target URL. Use ?url=https://...' }), { 
      status: 400, headers: { 'Content-Type': 'application/json', ...corsHeaders() }
    });
  }
  
  let target;
  try { target = new URL(targetUrl); } catch(e) {
    return new Response(JSON.stringify({ error: 'Invalid URL' }), { status: 400, headers: { 'Content-Type': 'application/json' }});
  }
  
  for (const [k,v] of url.searchParams) {
    if (k !== 'url') target.searchParams.append(k, v);
  }
  
  const h = new Headers();
  const allow = ['accept','accept-language','authorization','cache-control','content-type','cookie','origin','referer','user-agent','x-csrf-token','x-requested-with'];
  for (const [k,v] of request.headers) { if (allow.includes(k.toLowerCase())) h.set(k,v); }
  h.set('Host', target.hostname);
  h.set('X-Forwarded-For', [1,2,3,4].map(() => Math.floor(Math.random()*254)+1).join('.'));
  
  try {
    const resp = await fetch(target.toString(), {
      method: request.method,
      headers: h,
      body: ['GET','HEAD'].includes(request.method) ? null : request.body
    });
    
    const rh = new Headers();
    for (const [k,v] of resp.headers) {
      if (!['content-encoding','content-length','transfer-encoding'].includes(k.toLowerCase())) rh.set(k,v);
    }
    Object.entries(corsHeaders()).forEach(([k,v]) => rh.set(k,v));
    
    return new Response(resp.body, { status: resp.status, headers: rh });
  } catch(e) {
    return new Response(JSON.stringify({ error: e.message }), { status: 502, headers: { 'Content-Type': 'application/json' }});
  }
}

function corsHeaders() {
  return {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'GET,POST,PUT,DELETE,OPTIONS,PATCH,HEAD',
    'Access-Control-Allow-Headers': '*'
  };
}`;

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    
    if (request.method === "OPTIONS") {
      return corsResponse();
    }

    const apiKey = env.API_KEY || "change-me";
    const cfToken = env.CF_API_TOKEN;
    const cfAccountId = env.CF_ACCOUNT_ID;
    
    // === PUBLIC ENDPOINTS ===
    
    // Home - show usage
    if (url.pathname === "/") {
      return jsonResponse({
        name: "CF Proxy Pool",
        version: "1.0.0",
        endpoints: {
          public: {
            "/ip": "Check this worker's egress IP",
            "/pool": "Show proxy pool status",
            "/proxy?url=X": "Proxy request through pool (auto-rotation)",
            "/direct?url=X": "Proxy request directly (no pool)"
          },
          admin: {
            "/create?count=N": "Deploy N proxy workers",
            "/list": "List all proxy workers",
            "/delete?name=X": "Delete a proxy worker",
            "/cleanup": "Delete all proxy workers",
            "/test": "Test all proxies and show IPs"
          }
        },
        auth: "Admin endpoints require X-API-Key header"
      });
    }
    
    // IP check
    if (url.pathname === "/ip") {
      return handleIPCheck();
    }
    
    // === AUTH CHECK FOR ADMIN ENDPOINTS ===
    const authKey = request.headers.get("X-API-Key");
    const isAuthed = authKey === apiKey;
    
    // === ADMIN ENDPOINTS (require auth + CF credentials) ===
    
    if (url.pathname === "/create") {
      if (!isAuthed) return jsonResponse({ error: "Unauthorized" }, 401);
      if (!cfToken || !cfAccountId) {
        return jsonResponse({ error: "CF_API_TOKEN and CF_ACCOUNT_ID env vars required" }, 500);
      }
      const count = parseInt(url.searchParams.get("count") || "1");
      return handleCreate(cfToken, cfAccountId, count);
    }
    
    if (url.pathname === "/list") {
      if (!isAuthed) return jsonResponse({ error: "Unauthorized" }, 401);
      if (!cfToken || !cfAccountId) {
        return jsonResponse({ error: "CF_API_TOKEN and CF_ACCOUNT_ID env vars required" }, 500);
      }
      return handleList(cfToken, cfAccountId);
    }
    
    if (url.pathname === "/delete") {
      if (!isAuthed) return jsonResponse({ error: "Unauthorized" }, 401);
      if (!cfToken || !cfAccountId) {
        return jsonResponse({ error: "CF_API_TOKEN and CF_ACCOUNT_ID env vars required" }, 500);
      }
      const name = url.searchParams.get("name");
      if (!name) return jsonResponse({ error: "name parameter required" }, 400);
      return handleDelete(cfToken, cfAccountId, name);
    }
    
    if (url.pathname === "/cleanup") {
      if (!isAuthed) return jsonResponse({ error: "Unauthorized" }, 401);
      if (!cfToken || !cfAccountId) {
        return jsonResponse({ error: "CF_API_TOKEN and CF_ACCOUNT_ID env vars required" }, 500);
      }
      return handleCleanup(cfToken, cfAccountId);
    }
    
    // === PROXY ENDPOINTS ===
    
    if (url.pathname === "/pool") {
      if (!cfToken || !cfAccountId) {
        return jsonResponse({ error: "CF credentials not configured", direct_only: true });
      }
      return handlePoolStatus(cfToken, cfAccountId);
    }
    
    if (url.pathname === "/test") {
      if (!cfToken || !cfAccountId) {
        return handleDirectProxy(request, url);
      }
      return handleTestAll(cfToken, cfAccountId);
    }
    
    if (url.pathname === "/proxy" || url.pathname.startsWith("/proxy/")) {
      if (!cfToken || !cfAccountId) {
        return handleDirectProxy(request, url);
      }
      return handlePoolProxy(request, url, cfToken, cfAccountId);
    }
    
    if (url.pathname === "/direct" || url.pathname.startsWith("/direct/")) {
      return handleDirectProxy(request, url);
    }
    
    // Default: try pool proxy, fall back to direct
    return handleSmartProxy(request, url, cfToken, cfAccountId);
  }
};


// === CLOUDFLARE API FUNCTIONS ===

async function getSubdomain(token, accountId) {
  const resp = await fetch(
    `https://api.cloudflare.com/client/v4/accounts/${accountId}/workers/subdomain`,
    { headers: { "Authorization": `Bearer ${token}` } }
  );
  const data = await resp.json();
  return data.result?.subdomain;
}

async function handleCreate(token, accountId, count) {
  const results = { created: [], failed: [] };
  const subdomain = await getSubdomain(token, accountId);
  
  if (!subdomain) {
    return jsonResponse({ error: "Could not get workers subdomain. Visit CF dashboard to initialize." }, 500);
  }
  
  for (let i = 0; i < count; i++) {
    const name = `cfproxy-${Date.now()}-${randomString(6)}`;
    
    try {
      // Create worker script
      const formData = new FormData();
      formData.append("metadata", JSON.stringify({
        body_part: "script",
        main_module: "worker.js"
      }));
      formData.append("script", new Blob([PROXY_WORKER_SCRIPT], { type: "application/javascript" }), "worker.js");
      
      const createResp = await fetch(
        `https://api.cloudflare.com/client/v4/accounts/${accountId}/workers/scripts/${name}`,
        {
          method: "PUT",
          headers: { "Authorization": `Bearer ${token}` },
          body: formData
        }
      );
      
      if (!createResp.ok) {
        const err = await createResp.json();
        results.failed.push({ name, error: err.errors?.[0]?.message || "Unknown error" });
        continue;
      }
      
      // Enable on subdomain
      await fetch(
        `https://api.cloudflare.com/client/v4/accounts/${accountId}/workers/scripts/${name}/subdomain`,
        {
          method: "POST",
          headers: { 
            "Authorization": `Bearer ${token}`,
            "Content-Type": "application/json"
          },
          body: JSON.stringify({ enabled: true })
        }
      );
      
      const workerUrl = `https://${name}.${subdomain}.workers.dev`;
      results.created.push({ name, url: workerUrl });
      
    } catch (e) {
      results.failed.push({ name, error: e.message });
    }
  }
  
  return jsonResponse({
    ...results,
    summary: {
      requested: count,
      created: results.created.length,
      failed: results.failed.length
    }
  });
}

async function handleList(token, accountId) {
  const subdomain = await getSubdomain(token, accountId);
  
  const resp = await fetch(
    `https://api.cloudflare.com/client/v4/accounts/${accountId}/workers/scripts`,
    { headers: { "Authorization": `Bearer ${token}` } }
  );
  
  const data = await resp.json();
  const workers = [];
  
  for (const script of data.result || []) {
    if (script.id.startsWith("cfproxy-")) {
      workers.push({
        name: script.id,
        url: `https://${script.id}.${subdomain}.workers.dev`,
        created: script.created_on
      });
    }
  }
  
  return jsonResponse({
    workers,
    count: workers.length
  });
}

async function handleDelete(token, accountId, name) {
  const resp = await fetch(
    `https://api.cloudflare.com/client/v4/accounts/${accountId}/workers/scripts/${name}`,
    {
      method: "DELETE",
      headers: { "Authorization": `Bearer ${token}` }
    }
  );
  
  if (resp.ok || resp.status === 404) {
    return jsonResponse({ success: true, deleted: name });
  }
  
  const err = await resp.json();
  return jsonResponse({ success: false, error: err.errors?.[0]?.message }, 500);
}

async function handleCleanup(token, accountId) {
  const listResp = await handleList(token, accountId);
  const listData = await listResp.json();
  
  const results = { deleted: [], failed: [] };
  
  for (const worker of listData.workers || []) {
    const resp = await fetch(
      `https://api.cloudflare.com/client/v4/accounts/${accountId}/workers/scripts/${worker.name}`,
      {
        method: "DELETE",
        headers: { "Authorization": `Bearer ${token}` }
      }
    );
    
    if (resp.ok || resp.status === 404) {
      results.deleted.push(worker.name);
    } else {
      results.failed.push(worker.name);
    }
  }
  
  return jsonResponse(results);
}


// === PROXY HANDLERS ===

async function handleIPCheck() {
  try {
    const resp = await fetch("https://api.ipify.org?format=json");
    const data = await resp.json();
    return jsonResponse({ ip: data.ip, type: "direct" });
  } catch (e) {
    return jsonResponse({ error: e.message }, 500);
  }
}

async function handlePoolStatus(token, accountId) {
  const listResp = await handleList(token, accountId);
  const listData = await listResp.json();
  
  const results = {
    direct: null,
    pool: []
  };
  
  // Check direct IP
  try {
    const resp = await fetch("https://api.ipify.org?format=json");
    const data = await resp.json();
    results.direct = { ip: data.ip, status: "ok" };
  } catch (e) {
    results.direct = { error: e.message, status: "error" };
  }
  
  // Check each proxy
  for (const worker of listData.workers || []) {
    try {
      const resp = await fetch(`${worker.url}/ip`, { signal: AbortSignal.timeout(10000) });
      const data = await resp.json();
      results.pool.push({ url: worker.url, ip: data.ip, status: "ok" });
    } catch (e) {
      results.pool.push({ url: worker.url, error: e.message, status: "error" });
    }
  }
  
  const allIPs = [results.direct?.ip, ...results.pool.map(p => p.ip)].filter(Boolean);
  const uniqueIPs = [...new Set(allIPs)];
  
  return jsonResponse({
    ...results,
    summary: { total: results.pool.length + 1, unique_ips: uniqueIPs.length, ips: uniqueIPs }
  });
}

async function handleTestAll(token, accountId) {
  const listResp = await handleList(token, accountId);
  const listData = await listResp.json();
  const results = [];
  
  // Test direct - get real egress IP
  try {
    const start = Date.now();
    const resp = await fetch("https://httpbin.org/ip");
    const data = await resp.json();
    const ip = (data.origin || "").split(",")[0].trim();
    results.push({ proxy: "direct", ip, latency_ms: Date.now() - start, status: "ok" });
  } catch (e) {
    results.push({ proxy: "direct", error: e.message, status: "error" });
  }
  
  // Test pool - use httpbin/headers to see the X-Forwarded-For each proxy sends
  for (const worker of listData.workers || []) {
    try {
      const start = Date.now();
      const resp = await fetch(`${worker.url}?url=${encodeURIComponent("https://httpbin.org/headers")}`, {
        signal: AbortSignal.timeout(15000)
      });
      const text = await resp.text();
      let ip = "unknown";
      try {
        const data = JSON.parse(text);
        // Get the X-Forwarded-For header that the proxy sent
        ip = data.headers?.["X-Forwarded-For"] || data.headers?.["x-forwarded-for"] || "unknown";
        // Take first IP if multiple
        if (ip.includes(",")) ip = ip.split(",")[0].trim();
      } catch {}
      results.push({ proxy: worker.url, ip, latency_ms: Date.now() - start, status: "ok" });
    } catch (e) {
      results.push({ proxy: worker.url, error: e.message, status: "error" });
    }
  }
  
  const uniqueIPs = [...new Set(results.filter(r => r.ip && r.ip !== "unknown").map(r => r.ip))];
  return jsonResponse({
    results,
    summary: { total: results.length, ok: results.filter(r => r.status === "ok").length, unique_ips: uniqueIPs.length }
  });
}

async function handlePoolProxy(request, url, token, accountId) {
  const listResp = await handleList(token, accountId);
  const listData = await listResp.json();
  const workers = listData.workers || [];
  
  if (workers.length === 0) {
    return handleDirectProxy(request, url);
  }
  
  // Random selection
  const proxy = workers[Math.floor(Math.random() * workers.length)];
  const targetUrl = getTargetUrl(url, request.headers);
  
  if (!targetUrl) {
    return jsonResponse({ error: "No target URL. Use ?url=https://..." }, 400);
  }
  
  try {
    const proxyUrl = `${proxy.url}?url=${encodeURIComponent(targetUrl)}`;
    const resp = await fetch(proxyUrl, {
      method: request.method,
      headers: filterHeaders(request.headers),
      body: ["GET", "HEAD"].includes(request.method) ? null : request.body
    });
    
    const headers = new Headers(resp.headers);
    headers.set("X-Proxy-Used", proxy.url);
    headers.set("Access-Control-Allow-Origin", "*");
    headers.set("Access-Control-Expose-Headers", "X-Proxy-Used");
    
    return new Response(resp.body, { status: resp.status, headers });
  } catch (e) {
    return handleDirectProxy(request, url);
  }
}

async function handleSmartProxy(request, url, token, accountId) {
  if (token && accountId) {
    return handlePoolProxy(request, url, token, accountId);
  }
  return handleDirectProxy(request, url);
}


async function handleDirectProxy(request, url) {
  const targetUrl = getTargetUrl(url, request.headers);
  
  if (!targetUrl) {
    return jsonResponse({
      error: "No target URL",
      usage: "?url=https://example.com or X-Target-URL header"
    }, 400);
  }
  
  let target;
  try {
    target = new URL(targetUrl);
  } catch (e) {
    return jsonResponse({ error: "Invalid URL" }, 400);
  }
  
  // Forward query params
  for (const [k, v] of url.searchParams) {
    if (k !== "url") target.searchParams.append(k, v);
  }
  
  const headers = new Headers();
  const allow = ["accept", "accept-language", "authorization", "cache-control", "content-type", 
                 "cookie", "origin", "referer", "user-agent", "x-csrf-token", "x-requested-with"];
  
  for (const [k, v] of request.headers) {
    if (allow.includes(k.toLowerCase())) headers.set(k, v);
  }
  
  headers.set("Host", target.hostname);
  headers.set("X-Forwarded-For", randomIP());
  
  if (!headers.has("User-Agent")) {
    headers.set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36");
  }
  
  try {
    const resp = await fetch(target.toString(), {
      method: request.method,
      headers,
      body: ["GET", "HEAD"].includes(request.method) ? null : request.body
    });
    
    const respHeaders = new Headers();
    for (const [k, v] of resp.headers) {
      if (!["content-encoding", "content-length", "transfer-encoding"].includes(k.toLowerCase())) {
        respHeaders.set(k, v);
      }
    }
    respHeaders.set("Access-Control-Allow-Origin", "*");
    respHeaders.set("X-Proxy-Used", "direct");
    
    return new Response(resp.body, { status: resp.status, headers: respHeaders });
  } catch (e) {
    return jsonResponse({ error: e.message }, 502);
  }
}

// === HELPERS ===

function getTargetUrl(url, headers) {
  return url.searchParams.get("url") || headers.get("X-Target-URL") || null;
}

function filterHeaders(headers) {
  const filtered = new Headers();
  const skip = ["host", "cf-connecting-ip", "cf-ray", "cf-ipcountry", "x-api-key"];
  for (const [k, v] of headers) {
    if (!skip.includes(k.toLowerCase())) filtered.set(k, v);
  }
  return filtered;
}

function randomIP() {
  return [1, 2, 3, 4].map(() => Math.floor(Math.random() * 254) + 1).join(".");
}

function randomString(len) {
  const chars = "abcdefghijklmnopqrstuvwxyz";
  return Array.from({ length: len }, () => chars[Math.floor(Math.random() * chars.length)]).join("");
}

function jsonResponse(data, status = 200) {
  return new Response(JSON.stringify(data, null, 2), {
    status,
    headers: { "Content-Type": "application/json", "Access-Control-Allow-Origin": "*" }
  });
}

function corsResponse() {
  return new Response(null, {
    status: 204,
    headers: {
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS",
      "Access-Control-Allow-Headers": "*"
    }
  });
}
