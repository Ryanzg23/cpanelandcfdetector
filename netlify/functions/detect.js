export async function handler(event) {
  try {
    const { domains } = JSON.parse(event.body || "{}");
    if (!Array.isArray(domains)) {
      return {
        statusCode: 400,
        body: JSON.stringify({ error: "Invalid input" })
      };
    }

    const results = [];

    for (const input of domains) {
      const originalInput = input.trim();

      // Normalize input → preserve subfolder, query, hash
      const startUrl = normalizeUrl(originalInput);

      let httpResult = "-";
      let httpVia = "-";
      let trail = [];

      try {
        const redirectData = await followRedirects(startUrl);
        trail = redirectData.trail;

        if (trail.length) {
          const finalStep = trail[trail.length - 1];
          const startHost = new URL(startUrl).hostname.replace(/^www\./, "");
          const finalHost = new URL(finalStep.url).hostname.replace(/^www\./, "");

          if (startHost === finalHost) {
            // Same domain → show canonical protocol + full path
            const finalUrl = new URL(finalStep.url);
            httpResult = `${finalUrl.protocol}//${finalUrl.host}${finalUrl.pathname}${finalUrl.search}`;
          } else {
            // Cross-domain redirect → show full URL with path
            httpResult = `301 to ${finalStep.url}`;
          }

          httpVia = finalStep.via || "-";
        }
      } catch {
        httpResult = "Domain not active";
      }

      results.push({
        domain: originalInput,
        cloudflare: "-",     // handled elsewhere in your pipeline
        registrar: "-",      // handled elsewhere
        nameservers: "-",    // handled elsewhere
        http_result: httpResult,
        http_via: httpVia,
        http_trail: trail
      });
    }

    return {
      statusCode: 200,
      body: JSON.stringify(results)
    };

  } catch (err) {
    return {
      statusCode: 500,
      body: JSON.stringify({ error: "Server error" })
    };
  }
}

/* ================= HELPERS ================= */

function normalizeUrl(input) {
  if (!/^https?:\/\//i.test(input)) {
    return "http://" + input;
  }
  return input;
}

async function followRedirects(startUrl, maxHops = 10) {
  let currentUrl = startUrl;
  const trail = [];

  for (let i = 0; i < maxHops; i++) {
    const res = await fetch(currentUrl, {
      redirect: "manual"
    });

    const server = res.headers.get("server") || "";
    const via = server.toLowerCase().includes("cloudflare")
      ? "Cloudflare"
      : "htaccess";

    trail.push({
      url: currentUrl,
      status: res.status,
      via
    });

    // Handle redirects
    if (res.status >= 300 && res.status < 400) {
      const location = res.headers.get("location");
      if (!location) break;

      // IMPORTANT: resolve relative redirects correctly
      currentUrl = new URL(location, currentUrl).toString();
      continue;
    }

    break;
  }

  // HTTPS preference check (same full path)
  if (currentUrl.startsWith("http://")) {
    try {
      const httpsUrl = currentUrl.replace(/^http:/, "https:");
      const res = await fetch(httpsUrl, { redirect: "manual" });

      if (res.status >= 200 && res.status < 400) {
        const server = res.headers.get("server") || "";
        trail.push({
          url: httpsUrl,
          status: res.status,
          via: server.toLowerCase().includes("cloudflare")
            ? "Cloudflare"
            : "htaccess"
        });
        currentUrl = httpsUrl;
      }
    } catch {}
  }

  return { trail };
}
