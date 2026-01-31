export async function handler(event) {
  try {
    const { domains } = JSON.parse(event.body || "{}");
    if (!Array.isArray(domains)) {
      return {
        statusCode: 400,
        body: "Invalid input"
      };
    }

    /* ========= CSV SOURCES ========= */
    const CF_CSV =
      "https://docs.google.com/spreadsheets/d/e/2PACX-1vQ2U3uOILXKnV9VTDJgH2LzuP9uG2SGRf_w65CSL9VXcwIyFrWNNpmycqSQwgl5SwuP6N2HQI8ibXWv/pub?output=csv&gid=281551120";

    const PAGES_CSV =
      "https://docs.google.com/spreadsheets/d/1AtmjzUR_iGHCUE_tYLMAM9BP8Zx37nGiU0g632f2594/pub?output=csv&gid=1856733993";

    const cfList = await loadCsv(CF_CSV);
    const pagesList = await loadCsv(PAGES_CSV);

    const results = [];

    for (const input of domains) {
      const rawInput = input.trim();
      const hostname = extractHostname(rawInput);
      const startUrl = normalizeUrl(rawInput);

      let cloudflare = "-";
      let registrar = "-";
      let nameservers = "-";
      let http_result = "-";
      let http_via = "-";
      let http_trail = [];

      /* ========= NAMESERVERS ========= */
      let foundNS = [];
      try {
        const nsRes = await fetch(
          `https://dns.google/resolve?name=${hostname}&type=NS`
        );
        const nsJson = await nsRes.json();

        if (nsJson.Answer) {
          foundNS = nsJson.Answer.map(n =>
            n.data.replace(/\.$/, "").toLowerCase()
          );
          nameservers = foundNS.join(", ");
        }
      } catch {}

      /* ========= CLOUDFLARE (WORKING LOGIC) ========= */
      if (foundNS.length) {
        for (const row of cfList) {
          const ns1 = row["Nameserver 1"]?.trim().toLowerCase();
          const ns2 = row["Nameserver 2"]?.trim().toLowerCase();
          const email = row["Cloudflare Email"]?.trim();

          if (
            ns1 &&
            ns2 &&
            foundNS.includes(ns1) &&
            foundNS.includes(ns2)
          ) {
            cloudflare = email || "-";
            break;
          }
        }
      }

      /* ========= pages.dev ========= */
      if (hostname.endsWith(".pages.dev")) {
        const match = pagesList.find(r =>
          r.Domain &&
          normalizeDomain(r.Domain) === normalizeDomain(hostname)
        );
        cloudflare = match ? match.Email : "Not listed";
      }

      /* ========= REGISTRAR ========= */
      try {
        const whoisRes = await fetch(
          `https://rdap.org/domain/${hostname}`
        );
        const whois = await whoisRes.json();
        registrar =
          whois.entities?.find(e => e.roles?.includes("registrar"))
            ?.vcardArray?.[1]
            ?.find(v => v[0] === "fn")?.[3] || "-";
      } catch {}

      /* ========= HTTP REDIRECTS (SIMPLE + STABLE) ========= */
      try {
        const res = await fetch(startUrl, { redirect: "manual" });
        if (res.status >= 300 && res.status < 400) {
          const loc = res.headers.get("location");
          if (loc) {
            const finalUrl = new URL(loc, startUrl).toString();
            http_result = `301 to ${finalUrl}`;
            http_via = res.headers.get("server")?.toLowerCase().includes("cloudflare")
              ? "Cloudflare"
              : "Origin";
            http_trail = [{
              url: startUrl,
              status: res.status,
              via: http_via
            }];
          }
        } else if (res.status === 200) {
          http_result = startUrl.startsWith("https://")
            ? startUrl
            : startUrl.replace(/^http:/, "https:");
          http_via = res.headers.get("server")?.toLowerCase().includes("cloudflare")
            ? "Cloudflare"
            : "Origin";
        }
      } catch {
        http_result = "Domain not active";
      }

      results.push({
        domain: rawInput,
        cloudflare,
        registrar,
        nameservers,
        http_result,
        http_via,
        http_trail
      });
    }

    return {
      statusCode: 200,
      body: JSON.stringify(results)
    };
  } catch (err) {
    return {
      statusCode: 500,
      body: "Server error"
    };
  }
}

/* ========= HELPERS ========= */

function normalizeUrl(input) {
  if (!/^https?:\/\//i.test(input)) {
    return "http://" + input;
  }
  return input;
}

function extractHostname(input) {
  return normalizeUrl(input)
    .replace(/^https?:\/\//, "")
    .split("/")[0]
    .toLowerCase();
}

function normalizeDomain(d) {
  return d.replace(/^https?:\/\//, "")
    .replace(/\/$/, "")
    .toLowerCase();
}

async function loadCsv(url) {
  const res = await fetch(url);
  const text = await res.text();
  const [header, ...rows] = text.split(/\r?\n/);
  const keys = header.split(",").map(h => h.trim());

  return rows.map(r => {
    const obj = {};
    r.split(",").forEach((v, i) => {
      obj[keys[i]] = v?.replace(/^"|"$/g, "").trim();
    });
    return obj;
  });
}
