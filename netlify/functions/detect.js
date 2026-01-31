import dns from "dns/promises";

/* ================= DOMAIN NORMALIZER ================= */
function normalizeDomain(input) {
  try {
    input = input.trim();
    if (!input.startsWith("http")) input = "http://" + input;
    return new URL(input).hostname.replace(/^www\./, "").toLowerCase();
  } catch {
    return input.split("/")[0].replace(/^www\./, "").toLowerCase();
  }
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
async function detectHttp(domain, maxHops = 6) {
  let currentUrl = "http://" + domain;
  let trail = [];

  try {
    for (let i = 0; i < maxHops; i++) {
      const res = await fetch(currentUrl, { redirect: "manual" });
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

    const firstHost = domain.replace(/^www\./, "");
    const last = trail[trail.length - 1];
    const finalUrl = last.url;
    const finalHost = new URL(finalUrl).hostname.replace(/^www\./, "");

    // Same domain (http → https, www cleanup)
    if (firstHost === finalHost) {
      return {
        result: `${new URL(finalUrl).protocol}//${finalHost}`,
        via: last.via,
        trail
      };
    }

    // Cross-domain redirect → keep FULL path
    return {
      result: `301 to ${finalUrl}`,
      via: last.via,
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

/* ================= FALLBACK RESULT ================= */
function inactiveResult(domain) {
  return {
    domain,
    cloudflare: "-",
    registrar: "-",
    http_result: "Domain not active",
    http_via: "-",
    http_trail: [],
    nameservers: "-"
  };
}

/* ================= MAIN HANDLER ================= */
export async function handler(event) {
  try {
    const body = JSON.parse(event.body || "{}");
    const domains = [...new Set(
      (body.domains || []).map(normalizeDomain).filter(Boolean)
    )];

    if (!domains.length) {
      return {
        statusCode: 400,
        body: "No domains provided"
      };
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

    const results = [];

    for (const domain of domains) {
      try {
        const http = await detectHttp(domain);

        /* ===== pages.dev ===== */
        if (domain.endsWith(".pages.dev")) {
          results.push({
            domain,
            cloudflare: pagesMap[domain] || "Not listed",
            registrar: "Cloudflare, Inc.",
            http_result: http.result,
            http_via: http.via,
            http_trail: http.trail,
            nameservers: "-"
          });
          continue;
        }

        /* ===== NS LOOKUP ===== */
        let nameservers = [];
        try {
          nameservers = (await dns.resolveNs(domain))
            .map(n => n.replace(/\.$/, "").toLowerCase());
        } catch {}

        let cloudflare = "-";
        for (const r of cfNs) {
          if (nameservers.includes(r.ns1) && nameservers.includes(r.ns2)) {
            cloudflare = r.email;
            break;
          }
        }

        results.push({
          domain,
          cloudflare,
          registrar: await getRegistrar(domain),
          http_result: http.result,
          http_via: http.via,
          http_trail: http.trail,
          nameservers: nameservers.length
            ? nameservers.join(", ")
            : "-"
        });

      } catch {
        results.push(inactiveResult(domain));
      }
    }

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
