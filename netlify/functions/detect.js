import dns from "dns/promises";

/* ---------- CSV PARSER (ROBUST, QUOTED SAFE) ---------- */
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
  if (!cidr) return false;
  if (!cidr.includes("/")) return ip === cidr;
  const [range, bits] = cidr.split("/");
  const mask = bits == 0 ? 0 : (~0 << (32 - bits)) >>> 0;
  return (ipToInt(ip) & mask) === (ipToInt(range) & mask);
}

/* ---------- MAIN FUNCTION ---------- */
export async function handler(event) {
  try {
    const { domains } = JSON.parse(event.body || "{}");

    if (!domains || !domains.length) {
      return {
        statusCode: 400,
        body: JSON.stringify({ error: "No domains provided" })
      };
    }

    /* CSV SOURCES */
    const CPANEL_CSV =
      "https://docs.google.com/spreadsheets/d/1AtmjzUR_iGHCUE_tYLMAM9BP8Zx37nGiU0g632f2594/export?format=csv&gid=0";

    const CLOUDFLARE_CSV =
      "https://docs.google.com/spreadsheets/d/1AtmjzUR_iGHCUE_tYLMAM9BP8Zx37nGiU0g632f2594/export?format=csv&gid=281551120";

    /* FETCH CSVs (Node 18 native fetch) */
    const [cpRes, cfRes] = await Promise.all([
      fetch(CPANEL_CSV),
      fetch(CLOUDFLARE_CSV)
    ]);

    const cpanelList = parseCSV(await cpRes.text());
    const cfList = parseCSV(await cfRes.text());

    /* Normalize Cloudflare CSV entries */
    const cfEntries = cfList.map(r => ({
      email: r["Cloudflare Email"],
      ns: r.Nameservers
        .split(",")
        .map(n => n.trim().toLowerCase())
        .sort()
    }));

    const results = [];

    for (const domain of domains) {
      let ip = "-";
      let cpanel = "Unknown";
      let cloudflare = "No";
      let cfEmail = "-";
      let nameservers = [];

      /* ---------- A RECORD ---------- */
      try {
        const a = await dns.resolve4(domain);
        ip = a.find(i => i.includes(".")) || a[0];

        // Detect Cloudflare IP ranges
        const isCloudflareIP =
          ip.startsWith("104.") ||
          ip.startsWith("172.6") ||
          ip.startsWith("188.114.");

        if (!isCloudflareIP) {
          for (const row of cpanelList) {
            if (ipInRange(ip, row.IP)) {
              cpanel = row["Cpanel Name"];
              break;
            }
          }
        } else {
          cpanel = "Behind Cloudflare";
        }
      } catch {}

      /* ---------- NS RECORD ---------- */
      try {
        const ns = await dns.resolveNs(domain);
        nameservers = ns.map(n => n.toLowerCase()).sort();

        /* Hybrid Cloudflare detection */
        const isCloudflareNS = nameservers.every(n =>
          n.endsWith(".ns.cloudflare.com")
        );

        if (isCloudflareNS) {
          cloudflare = "Yes";
        }

        /* Strict CSV match for email */
        for (const row of cfEntries) {
          if (
            row.ns.length === 2 &&
            row.ns[0] === nameservers[0] &&
            row.ns[1] === nameservers[1]
          ) {
            cfEmail = row.email;
            break;
          }
        }
      } catch {}

      results.push({
        domain,
        ip,
        cpanel,
        cloudflare,
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
    return {
      statusCode: 500,
      body: JSON.stringify({ error: err.message })
    };
  }
}
