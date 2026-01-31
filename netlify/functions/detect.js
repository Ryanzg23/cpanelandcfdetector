export async function handler(event) {
  try {
    const { domains } = JSON.parse(event.body || "{}");
    if (!Array.isArray(domains)) {
      return { statusCode: 400, body: "Invalid input" };
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
      const domainInput = input.trim();
      const hostname = getHostname(domainInput);
      const startUrl = normalizeUrl(domainInput);

      let cloudflare = "-";
      let registrar = "-";
      let nameservers = "-";
      let http_result = "-";
      let http_via = "-";
      let http_trail = [];

      /* ========= DNS (Nameservers) ========= */
      let foundNS = [];
      try {
        const nsRes = await fetch(
          `https://dns.google/resolve?name=${hostname}&type=NS`
        );
        const nsJson = await nsRes.json();

        if (nsJson.Answer) {
          foundNS = nsJson.Answer.map(n =>
            normalizeNS(n.data)
          );
          nameservers = foundNS.join(", ");
        }
      } catch {}

      /* ========= CLOUDFLARE (normal domains) ========= */
      if (foundNS.length) {
        const foundSet = new Set(foundNS);

        for (const row of cfList) {
          const normalizedRow = {};
          for (const k in row) {
            normalizedRow[k.trim().toLowerCase()] = row[k]?.trim();
          }

          const ns1 = normalizeNS(normalizedRow.ns1 || "");
          const ns2 = normalizeNS(normalizedRow.ns2 || "");
          const email = normalizedRow["cloudflare email"];

          if (ns1 && ns2 && foundSet.has(ns1) && foundSet.has(ns2)) {
            cloudflare = email || "-";
            break;
          }
        }
      }

      /* ========= pages.dev ========= */
      if (hostname.endsWith(".pages.dev")) {
        const match = pagesList.find(r =>
          normalizeDomain(r.Domain) === normalizeDomain(hostname)
        );
        cloudflare = match ? match.Email : "Not listed";
      }

      /* ========= REGISTRAR ========= */
      try {
        const whoisRes = await fetch(`https://rdap.org/domain/${hostname}`);
        const whois = await whoisRes.json();
        registrar =
          whois.registrar?.name ||
          whois.entities?.find(e => e.roles?.includes("registrar"))
            ?.vcardArray?.[1]?.find(v => v[0] === "fn")?.[3] ||
          "-";
      } catch {}

      /* ========= HTTP REDIRECTS ========= */
      try {
        const redirectData = await followRedirects(startUrl);
        http_trail = redirectData.trail;

        if (http_trail.length) {
          const finalStep = http_trail.at(-1);
          const startHost = new URL(startUrl).hostname.replace(/^www\./, "");
          const finalHost = new URL(finalStep.url).hostname.replace(/^www\./, "");

          if (startHost === finalHost) {
            const u = new URL(finalStep.url);
            http_result = `${u.protocol}//${u.host}${u.pathname}${u.search}`;
          } else {
            http_result = `301 to ${finalStep.url}`;
          }

          http_via = finalStep.via || "-";
        }
      } catch {
        http_result = "Domain not active";
      }

      results.push({
        domain: domainInput,
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
    return { statusCode: 500, body: "Server error" };
  }
}

/* ========= HELPERS ========= */

function normalizeUrl(input) {
  if (!/^https?:\/\//i.test(input)) return "http://" + input;
  return input;
}

function getHostname(input) {
  return normalizeUrl(input)
    .replace(/^https?:\/\//, "")
    .split("/")[0]
    .toLowerCase();
}

function normalizeDomain(d) {
  return d.replace(/^https?:\/\//, "").replace(/\/$/, "").toLowerCase();
}

function normalizeNS(ns) {
  return ns.toLowerCase().trim().replace(/\.$/, "");
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

async function followRedirects(startUrl, maxHops = 10) {
  let currentUrl = startUrl;
  const trail = [];

  for (let i = 0; i < maxHops; i++) {
    const res = await fetch(currentUrl, { redirect: "manual" });
    const server = res.headers.get("server") || "";
    const via = server.toLowerCase().includes("cloudflare")
      ? "Cloudflare"
      : "Origin";

    trail.push({
      url: currentUrl,
      status: res.status,
      via
    });

    if (res.status >= 300 && res.status < 400) {
      const loc = res.headers.get("location");
      if (!loc) break;
      currentUrl = new URL(loc, currentUrl).toString();
      continue;
    }
    break;
  }

  if (currentUrl.startsWith("http://")) {
    try {
      const httpsUrl = currentUrl.replace(/^http:/, "https:");
      const res = await fetch(httpsUrl, { redirect: "manual" });
      if (res.status >= 200 && res.status < 400) {
        trail.push({
          url: httpsUrl,
          status: res.status,
          via: res.headers.get("server")?.toLowerCase().includes("cloudflare")
            ? "Cloudflare"
            : "Origin"
        });
      }
    } catch {}
  }

  return { trail };
}
