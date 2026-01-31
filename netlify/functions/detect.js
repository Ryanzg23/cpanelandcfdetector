import dns from "dns/promises";

/* ---------- CSV PARSER ---------- */
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

/* ---------- IP / CIDR ---------- */
function ipToInt(ip) {
  return ip.split(".").reduce((a, o) => (a << 8) + +o, 0) >>> 0;
}

function ipInRange(ip, cidr) {
  if (!cidr || !ip) return false;
  if (!cidr.includes("/")) return ip === cidr;

  const [range, bits] = cidr.split("/");
  const mask = bits == 0 ? 0 : (~0 << (32 - bits)) >>> 0;
  return (ipToInt(ip) & mask) === (ipToInt(range) & mask);
}

/* ---------- MAIN ---------- */
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
      let nameservers = [];

      /* ---------- A RECORDS ---------- */
      try {
        ips = await dns.resolve4(domain);
      } catch {
        ips = [];
      }

      const isCloudflareIP = ips.some(ip =>
        ip.startsWith("104.") ||
        ip.startsWith("172.6") ||
        ip.startsWith("188.114.")
      );

      if (isCloudflareIP) {
        cpanel = "Behind Cloudflare";
      } else {
        // Exact IP match (any A record)
        for (const row of cpanelIPs) {
          if (ips.includes(row.ip)) {
            cpanel = row.name;
            break;
          }
        }

        // CIDR fallback
        if (cpanel === "Unknown") {
          for (const row of cpanelIPs) {
            for (const ip of ips) {
              if (ipInRange(ip, row.ip)) {
                cpanel = row.name;
                break;
              }
            }
            if (cpanel !== "Unknown") break;
          }
        }
      }

      /* ---------- NS RECORDS ---------- */
      try {
        nameservers = (await dns.resolveNs(domain))
          .map(n => n.toLowerCase().replace(/\.$/, "").trim());
      } catch {
        nameservers = [];
      }

      for (const row of cfEntries) {
        if (
          nameservers.includes(row.ns1) &&
          nameservers.includes(row.ns2)
        ) {
          cfEmail = row.email;
          break;
        }
      }

      results.push({
        domain,
        ip: ips.join(", "),
        cpanel,
        cloudflare_email: cfEmail,
        nameservers: nameservers.join(", ")
      });
    }

    return {
      statusCode: 200,
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(results)
    };
  } catch (err) {
    console.error("Function crash:", err);
    return {
      statusCode: 500,
      body: JSON.stringify({ error: err.message })
    };
  }
}
