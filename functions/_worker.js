export default {
  async fetch(request, env) {
    const reqUrl = new URL(request.url);

    if (reqUrl.pathname === "/proxy") {
      const corsHeaders = {
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Methods": "GET, HEAD, OPTIONS",
        "Access-Control-Allow-Headers": "Range, Content-Type",
        "Access-Control-Expose-Headers": "Content-Range, Content-Length, Accept-Ranges",
      };

      if (request.method === "OPTIONS") {
        return new Response(null, { status: 204, headers: corsHeaders });
      }

      const target = reqUrl.searchParams.get("url");
      if (!target || !target.startsWith("https://archive.org/")) {
        return new Response("Invalid archive.org URL", { status: 400, headers: corsHeaders });
      }

      const fwdHeaders = new Headers();
      if (request.headers.has("Range")) {
        fwdHeaders.set("Range", request.headers.get("Range"));
      }
      fwdHeaders.set("User-Agent", "Mozilla/5.0");

      const upstream = await fetch(target, {
        method: request.method === "HEAD" ? "HEAD" : "GET",
        headers: fwdHeaders,
        redirect: "follow",
      });

      const outHeaders = new Headers();
      for (const h of ["content-type", "content-length", "content-range", "accept-ranges", "etag", "last-modified"]) {
        if (upstream.headers.has(h)) outHeaders.set(h, upstream.headers.get(h));
      }
      for (const [k, v] of Object.entries(corsHeaders)) outHeaders.set(k, v);
      outHeaders.set("Cache-Control", "no-store");

      return new Response(upstream.body, {
        status: upstream.status,
        statusText: upstream.statusText,
        headers: outHeaders,
      });
    }

    return env.ASSETS.fetch(request);
  },
};
