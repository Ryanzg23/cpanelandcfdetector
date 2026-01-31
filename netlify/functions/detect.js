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

/* ---------- RDAP REGISTRAR ---------- */
async function getRegistrar(domain) {
  try {
    const res = await fetch(`https://rdap.org/domain/${domain}`);
    if (!res.ok) return "-";

    const data = await res.json();

    const registrar =
      data.entities?.find(e =>
        e.roles?.includes("registrar")
      )?.vcardArray?.[1]
        ?.find(v => v[0] === "fn")?.[3];

    return registrar || "-";
  } catch {
    return "-";
  }
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

    /* CLOUDFLARE CSV */
    const CLOUDFLARE_CSV =
      "https://docs.google.com/spreadsheets/d/1AtmjzUR_iGHCUE_tYLMAM9BP8Zx37nGiU0g632f2594/export?format=csv&gid=281551120";

    const cfRes = await fetch(CLOUDFLARE_CSV);
    const cfList = parseCSV(await cfRes.text());

    const cfEntries = cfList.map(r => ({
      email: r["Cloudflare Email"],
      ns1: r["Nameserver 1"].toLowerCase().replace(/\.$/, "").trim(),
      ns2: r["Nameserver 2"].toLowerCase().replace(/\.$/, "").trim()
    }));

    const results = [];

    for (const domain of domains) {
      let ips = [];
      let registrar = "-";
      let cfEmail = "-";
      let nameservers = [];

      /* A RECORD */
      try {
        ips = await dns.resolve4(domain);
      } catch {}

      /* NS RECORD */
      try {
        nameservers = (await dns.resolveNs(domain))
          .map(n => n.toLowerCase().replace(/\.$/, "").trim());
      } catch {}

      /* Cloudflare Email Match */
      for (const row of cfEntries) {
        if (
          nameservers.includes(row.ns1) &&
          nameservers.includes(row.ns2)
        ) {
          cfEmail = row.email;
          break;
        }
      }

      /* Registrar (RDAP) */
      registrar = await getRegistrar(domain);

      results.push({
        domain,
        ip: ips.join(", "),
        registrar,
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
