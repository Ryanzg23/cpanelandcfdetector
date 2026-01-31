import dns from "dns/promises";

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
    const registrar =
      data.entities?.find(e => e.roles?.includes("registrar"))
        ?.vcardArray?.[1]
        ?.find(v => v[0] === "fn")?.[3];

    return registrar || "-";
  } catch {
    return "-";
  }
}

/* ================= MAIN FUNCTION ================= */
export async function handler(event) {
  try {
    const body = JSON.parse(event.body || "{}");
    const domains = Array.isArray(body.domains) ? body.domains : [];

    if (!domains.length) {
      return {
        statusCode: 400,
        body: JSON.stringify({ error: "No domains provided" })
      };
    }

    /* ===== CSV SOURCES ===== */
    const CPANEL_CSV =
      "https://docs.google.com/spreadsheets/d/1AtmjzUR_iGHCUE_tYLMAM9BP8Zx37nGiU0g632f2594/export?format=csv&gid=0";

    const CLOUDFLARE_CSV =
      "https://docs.google.com/spreadsheets/d/1AtmjzUR_iGHCUE_tYLMAM9BP8Zx37nGiU0g632f2594/export?format=csv&gid=281551120";

    const [cpRes, cfRes] = await Promise.all([
      fetch(CPANEL_CSV),
      fetch(CLOUDFLARE_CSV)
    ]);

    const cpanelList = parseCSV(await cpRes.text());
    const cfList = parseCSV(await cfRes.text());

    const cpanelIPs = cpanelList.map(r => ({
      name: r["Cpanel Name"],
      ip: r.IP
    }));

    const cfEntries = cfList.map(r => ({
      email: r["Cloudflare Email"],
      ns1: r["Nameserver 1"]?.toLowerCase().replace(/\.$/, "").trim(),
      ns2: r["Nameserver 2"]?.toLowerCase().replace(/\.$/, "").trim()
    })).filter(r => r.ns1 && r.ns2);

    const results = [];

    for (const domain of domains) {
      let ips = [];
      let cpanel = "Unknown";
      let cfEmail = "-";
      let registrar = "-";
      let nameservers = [];

      /* ===== A RECORDS ===== */
      try {
        ips = await dns.resolve4(domain);
      } catch {}

      const isCloudflareIP = ips.some(ip =>
        ip.startsWith("104.") ||
        ip.startsWith("172.6") ||
        ip.startsWith("188.114.")
      );

      const cfProxyStatus = isCloudflareIP ? "Proxied" : "DNS-only";

      if (!isCloudflareIP) {
        for (const row of cpanelIPs) {
          if (ips.includes(row.ip)) {
            cpanel = row.name;
            break;
          }
        }
      } else {
        cpanel = "Behind Cloudflare";
      }

      /* ===== NS RECORDS ===== */
      try {
        nameservers = (await dns.resolveNs(domain))
          .map(n => n.toLowerCase().replace(/\.$/, "").trim());
      } catch {}

      for (const row of cfEntries) {
        if (
          nameservers.includes(row.ns1) &&
          nameservers.includes(row.ns2)
        ) {
          cfEmail = row.email;
          break;
        }
      }

      /* ===== REGISTRAR ===== */
      registrar = await getRegistrar(domain);

      results.push({
        domain,
        ip: ips.join(", "),
        registrar,
        cloudflare_email: cfEmail,
        cf_proxy: cfProxyStatus,
        cpanel,
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
