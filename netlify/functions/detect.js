import dns from "dns/promises";

/* ================= DOMAIN NORMALIZER ================= */
/* hostname only (for DNS / CF / registrar) */
function normalizeDomain(input) {
  try {
    input = input.trim();
    if (!input.startsWith("http")) input = "http://" + input;
    return new URL(input).hostname.replace(/^www\./, "").toLowerCase();
  } catch {
    return input.split("/")[0].replace(/^www\./, "").toLowerCase();
  }
}

/* ================= URL NORMALIZER ================= */
/* preserves path, query, hash */
function normalizeUrl(input) {
  input = input.trim();
  if (!input.startsWith("http://") && !input.startsWith("https://")) {
    return "http://" + input;
  }
  return input;
}

/* ================= CSV PARSER ================= */
function parseCSV(text) {
  const rows = [];
  let row = [];
  let val = "";
  let inQuotes = false;

  for (let c of text) {
    if (c === '"') inQuotes = !inQuotes;
    else if (c === "," && !inQuotes) {
      row.push(val);
      val = "";
    } else if ((c === "\n" || c === "\r") && !inQuotes) {
      if (row.length || val) {
        row.push(val);
        rows.push(row);
      }
      row = [];
      val = "";
    } else {
      val += c;
    }
  }

  if (row.length || val) {
    row.push(val);
    rows.push(row);
  }

  const headers = rows.shift().map(h => h.trim());
  return rows.map(r => {
    const o = {};
    headers.forEach((h, i) => o[h] = (r[i] || "").trim());
    return o;
  });
}

/* ================= REGISTRAR ================= */
async function getRegistrar(domain) {
  try {
    const res = await fetch(`https://rdap.org/domain/${domain}`);
    if (!res.ok) return "-";
    const data = await res.json();
    return (
      data.entities?.find(e => e.roles?.includes("registrar"))
        ?.vcardArray?.[1]
        ?.find(v => v[0] === "fn")?.[3] || "-"
    );
  } catch {
    return "-";
  }
}

/* ================= HTTP / 301 DETECTION ================= */
/* FULL PATH SAFE */
async function detectHttp(inputUrl, maxHops = 6) {
  let trail = [];
  let currentUrl = normalizeUrl(inputUrl);

  try {
    for (let i = 0; i < maxHops; i++) {
      const res = await fetch(currentUrl, {
          redirect: "manual",
          headers: {
            "User-Agent": "Mozilla/5.0 (Bulk SEO Meta Viewer)",
            "Accept": "text/html,application/xhtml+xml",
            "Accept-Language": "en-US,en;q=0.9"
          }
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

      const location = res.headers.get("location");
      if (res.status >= 300 && res.status < 400 && location) {
        currentUrl = new URL(location, currentUrl).toString();
        continue;
      }
      break;
    }

    let finalUrl = currentUrl;

    // HTTPS preference (preserves path)
    if (finalUrl.startsWith("http://")) {
      try {
        const httpsUrl = finalUrl.replace(/^http:/, "https:");
        const httpsRes = await fetch(httpsUrl, { redirect: "manual" });
        if (httpsRes.status >= 200 && httpsRes.status < 400) {
          trail.push({
            url: httpsUrl,
            status: httpsRes.status,
            via: httpsRes.headers.get("server")?.toLowerCase().includes("cloudflare")
              ? "Cloudflare"
              : "htaccess"
          });
          finalUrl = httpsUrl;
        }
      } catch {}
    }

    const startHost = new URL(normalizeUrl(inputUrl)).hostname.replace(/^www\./, "");
    const finalHost = new URL(finalUrl).hostname.replace(/^www\./, "");

    if (startHost === finalHost) {
      const u = new URL(finalUrl);
      return {
        result: `${u.protocol}//${u.host}${u.pathname}${u.search}`,
        via: trail.at(-1)?.via || "-",
        trail
      };
    }

    return {
      result: `301 to ${finalUrl}`,
      via: trail.at(-1)?.via || "-",
      trail
    };

  } catch {
    return {
      result: "Domain not active",
      via: "-",
      trail: []
    };
  }
}

/* ================= FALLBACK ================= */
function inactiveResult(input) {
  return {
    domain: input,
    cloudflare: "-",
    registrar: "-",
    http_result: "Domain not active",
    http_via: "-",
    http_trail: [],
    nameservers: "-"
  };
}

/* ================= PARALLEL RUNNER ================= */
async function runWithConcurrency(items, limit, worker) {
  const results = [];
  const queue = items.map((item, index) => ({ item, index }));

  const runners = Array.from({ length: limit }, async () => {
    while (queue.length) {
      const { item, index } = queue.shift();
      try {
        const result = await worker(item);
        results.push({ index, result });
      } catch {
        results.push({ index, result: inactiveResult(item) });
      }
    }
  });

  await Promise.all(runners);

  // 🔑 Restore original order
  return results
    .sort((a, b) => a.index - b.index)
    .map(r => r.result);
}


/* ================= MAIN HANDLER ================= */
export async function handler(event) {
  try {
    const body = JSON.parse(event.body || "{}");

    /* KEEP FULL INPUT (PATH SAFE) */
    const inputs = [...new Set(
      (body.domains || []).map(d => d.trim()).filter(Boolean)
    )];

    if (!inputs.length) {
      return { statusCode: 400, body: "No domains provided" };
    }

    /* ===== CSV SOURCES ===== */
    const BASE =
      "https://docs.google.com/spreadsheets/d/1AtmjzUR_iGHCUE_tYLMAM9BP8Zx37nGiU0g632f2594/export?format=csv&gid=";

    const cfCsv = parseCSV(await (await fetch(BASE + "281551120")).text());
    const pagesCsv = parseCSV(await (await fetch(BASE + "1856733993")).text());

    const pagesMap = {};
    pagesCsv.forEach(r => {
      const d = normalizeDomain(r.Domain);
      if (d) pagesMap[d] = r.Cloudflare;
    });

    const cfNs = cfCsv.map(r => ({
      email: r["Cloudflare Email"],
      ns1: r["Nameserver 1"]?.toLowerCase(),
      ns2: r["Nameserver 2"]?.toLowerCase()
    }));

    const results = await runWithConcurrency(inputs, 5, async (input) => {
      const hostname = normalizeDomain(input);

      const http = await detectHttp(input);

      /* ===== pages.dev ===== */
      if (hostname.endsWith(".pages.dev")) {
        return {
          domain: input,
          cloudflare: pagesMap[hostname] || "Not listed",
          registrar: "Cloudflare, Inc.",
          http_result: http.result,
          http_via: http.via,
          http_trail: http.trail,
          nameservers: "-"
        };
      }

      /* ===== NS LOOKUP ===== */
      let nameservers = [];
      try {
        nameservers = (await dns.resolveNs(hostname))
          .map(n => n.replace(/\.$/, "").toLowerCase());
      } catch {}

      let cloudflare = "-";
      for (const r of cfNs) {
        if (nameservers.includes(r.ns1) && nameservers.includes(r.ns2)) {
          cloudflare = r.email;
          break;
        }
      }

      return {
        domain: input,
        cloudflare,
        registrar: await getRegistrar(hostname),
        http_result: http.result,
        http_via: http.via,
        http_trail: http.trail,
        nameservers: nameservers.length ? nameservers.join(", ") : "-"
      };
    });

    return {
      statusCode: 200,
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(results)
    };

  } catch (err) {
    return {
      statusCode: 500,
      body: JSON.stringify({ error: err.message })
    };
  }
}


