import dns from "dns/promises";

/* ================= DOMAIN NORMALIZER ================= */
function normalizeDomain(input) {
  try {
    input = input.trim();
    if (!input.startsWith("http")) input = "http://" + input;
    const url = new URL(input);
    return url.hostname.replace(/^www\./, "").toLowerCase();
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

  for (let i = 0; i < text.length; i++) {
    const c = text[i];

    if (c === '"') {
      inQuotes = !inQuotes;
    } else if (c === "," && !inQuotes) {
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
    const obj = {};
    headers.forEach((h, i) => {
      obj[h] = (r[i] || "").trim();
    });
    return obj;
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

/* ================= HTTP CHECK ================= */
async function detectHttp(domain) {
  try {
    const res = await fetch("http://" + domain, { redirect: "manual" });
    const location = res.headers.get("location");
    const server = res.headers.get("server") || "";

    const via = server.toLowerCase().includes("cloudflare")
      ? "Cloudflare"
      : "htaccess";

    if (res.status >= 300 && res.status < 400 && location) {
      const target = new URL(location, "http://" + domain);
      const base = domain.replace(/^www\./, "");
      const targetHost = target.hostname.replace(/^www\./, "");

      if (base === targetHost) {
        return {
          result: `${target.protocol}//${targetHost}`,
          via
        };
      }

      return {
        result: `301 to ${target.protocol}//${targetHost}`,
        via
      };
    }

    return { result: `https://${domain}`, via: "-" };
  } catch {
    return { result: "-", via: "-" };
  }
}

/* ================= MAIN ================= */
export async function handler(event) {
  const body = JSON.parse(event.body || "{}");
  const domains = [...new Set(
    (body.domains || []).map(normalizeDomain).filter(Boolean)
  )];

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
    const http = await detectHttp(domain);

    if (domain.endsWith(".pages.dev")) {
      results.push({
        domain,
        cloudflare: pagesMap[domain] || "Not listed",
        registrar: "Cloudflare, Inc.",
        http_result: http.result,
        http_via: http.via,
        nameservers: "-"
      });
      continue;
    }

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
      nameservers: nameservers.join(", ")
    });
  }

  return {
    statusCode: 200,
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(results)
  };
}
