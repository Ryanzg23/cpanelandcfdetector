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
    const next = text[i + 1];

    if (c === '"' && inQuotes && next === '"') {
      val += '"';
      i++;
    } else if (c === '"') {
      inQuotes = !inQuotes;
    } else if (c === "," && !inQuotes) {
      row.push(val);
      val = "";
    } else if ((c === "\n" || c === "\r") && !inQuotes) {
      if (val || row.length) {
        row.push(val);
        rows.push(row);
      }
      row = [];
      val = "";
    } else {
      val += c;
    }
  }

  if (val || row.length) {
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

/* ================= REGISTRAR (RDAP) ================= */
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

/* ================= MAIN ================= */
export async function handler(event) {
  try {
    const body = JSON.parse(event.body || "{}");
    const rawDomains = Array.isArray(body.domains) ? body.domains : [];

    const domains = [...new Set(
      rawDomains.map(normalizeDomain).filter(Boolean)
    )];

    if (!domains.length) {
      return { statusCode: 400, body: "No domains provided" };
    }

    /* ===== CSV SOURCES ===== */
    const BASE =
      "https://docs.google.com/spreadsheets/d/1AtmjzUR_iGHCUE_tYLMAM9BP8Zx37nGiU0g632f2594/export?format=csv&gid=";

    const CLOUDFLARE_CSV = BASE + "281551120";
    const PAGESDEV_CSV = BASE + "1856733993";

    const [cfRes, pgRes] = await Promise.all([
      fetch(CLOUDFLARE_CSV),
      fetch(PAGESDEV_CSV)
    ]);

    const cfList = parseCSV(await cfRes.text());
    const pagesList = parseCSV(await pgRes.text());

    /* ===== pages.dev MAP (AUTHORITATIVE) ===== */
    const pagesMap = {};
    for (const row of pagesList) {
      const d = normalizeDomain(row.Domain);
      if (d) pagesMap[d] = row.Cloudflare;
    }

    /* ===== Cloudflare NS MAP ===== */
    const cfEntries = cfList.map(r => ({
      email: r["Cloudflare Email"],
      ns1: r["Nameserver 1"]?.toLowerCase().replace(/\.$/, "").trim(),
      ns2: r["Nameserver 2"]?.toLowerCase().replace(/\.$/, "").trim()
    })).filter(r => r.ns1 && r.ns2);

    const results = [];

    for (const domain of domains) {
      let registrar = "-";
      let cfValue = "-";
      let nameservers = [];

      /* ===== pages.dev OVERRIDE ===== */
      if (domain.endsWith(".pages.dev") && pagesMap[domain]) {
        registrar = "Cloudflare, Inc.";
        cfValue = pagesMap[domain];

        results.push({
          domain,
          registrar,
          cloudflare: cfValue,
          nameservers: "-"
        });
        continue;
      }

      /* ===== NS LOOKUP ===== */
      try {
        nameservers = (await dns.resolveNs(domain))
          .map(n => n.toLowerCase().replace(/\.$/, "").trim());
      } catch {}

      /* ===== Cloudflare EMAIL via NS ===== */
      for (const row of cfEntries) {
        if (
          nameservers.includes(row.ns1) &&
          nameservers.includes(row.ns2)
        ) {
          cfValue = row.email;
          break;
        }
      }

      registrar = await getRegistrar(domain);

      results.push({
        domain,
        registrar,
        cloudflare: cfValue,
        nameservers: nameservers.join(", ")
      });
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
