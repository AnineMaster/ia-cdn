export async function onRequest(context) {
  const { request } = context;
  if (request.method === "OPTIONS") {
    return new Response(null, {
      headers: { "Access-Control-Allow-Origin": "*", "Access-Control-Allow-Methods": "GET, OPTIONS" },
    });
  }

  const u = new URL(request.url);
  const target = u.searchParams.get("url");
  const s = u.searchParams.get("s"), e = u.searchParams.get("e");
  if (!target) return new Response("Pages India Edge CDN Ready!", { status: 200 });

  const t = new URL(target);
  if (t.hostname !== "archive.org" && !t.hostname.endsWith(".archive.org")) {
    return new Response("Forbidden", { status: 403 });
  }

  const cache = caches.default;
  let res = await cache.match(request);
  if (res) return res;

  const isChunk = s !== null && e !== null;
  const h = new Headers({ "User-Agent": "Mozilla/5.0" });
  if (isChunk) h.set("Range", `bytes=${s}-${e}`);

  const up = await fetch(target, { headers: h, redirect: "follow" });
  const out = new Headers();
  for (const k of ["content-type", "content-length", "content-range"]) {
    if (up.headers.get(k)) out.set(k, up.headers.get(k));
  }
  out.set("Access-Control-Allow-Origin", "*");
  out.set("Access-Control-Expose-Headers", "Content-Range, X-Final-Url, CF-Cache-Status");
  out.set("X-Final-Url", up.url);
  out.set("Cache-Control", isChunk ? "public, max-age=31536000, immutable" : "public, max-age=60");

  const status = (isChunk && (up.status === 206 || up.status === 200)) ? 200 : up.status;
  res = new Response(up.body, { status, headers: out });
  if (status === 200) context.waitUntil(cache.put(request, res.clone()));
  return res;
}
