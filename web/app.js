const fileInput = document.getElementById("logFile");
const analyseBtn = document.getElementById("analyseBtn");
const statusPanel = document.getElementById("status");
const summary = document.getElementById("summary");
const statsContainer = document.getElementById("stats");
const threatsPanel = document.getElementById("threats");
const threatTable = document.getElementById("threatTable");
const tablesContainer = document.getElementById("tables");
const topIpsTable = document.getElementById("topIps");
const topUrlsTable = document.getElementById("topUrls");
const topAgentsTable = document.getElementById("topAgents");
const httpCodesTable = document.getElementById("httpCodes");

analyseBtn.addEventListener("click", () => {
  const file = fileInput.files[0];
  if (!file) {
    alert("Choisissez un fichier de logs.");
    return;
  }

  const reader = new FileReader();
  reader.onload = () => {
    const lines = reader.result.split(/\r?\n/).filter(line => line.trim());
    const { entries, invalidLines } = parseLogLines(lines);
    renderStatus(entries, invalidLines.length);
    renderSummary(entries);
    renderThreats(entries);
    renderTables(entries);
  };
  reader.readAsText(file, "UTF-8");
});

function parseLogLines(lines) {
  const regex = /^(\S+) \S+ (\S+) \[([^\]]+)\] "(\S+) (\S+) (\S+)" (\d{3}) (\d+|-) "(.*?)" "(.*?)"$/;
  const entries = [];
  let invalid = 0;

  lines.forEach((line) => {
    const m = line.match(regex);
    if (!m) {
      invalid += 1;
      return;
    }

    const timestamp = parseTimestamp(m[3]);
    entries.push({
      ip: m[1],
      user: m[2],
      timestamp,
      method: m[4],
      url: m[5],
      protocol: m[6],
      status: m[7],
      size: m[8] === "-" ? 0 : Number(m[8]),
      referer: m[9],
      agent: m[10],
      raw: line
    });
  });

  return { entries, invalidLines: invalid };
}

function parseTimestamp(text) {
  const months = { Jan: 0, Feb: 1, Mar: 2, Apr: 3, May: 4, Jun: 5, Jul: 6, Aug: 7, Sep: 8, Oct: 9, Nov: 10, Dec: 11 };
  const parts = text.match(/^(\d{2})\/(\w{3})\/(\d{4}):(\d{2}):(\d{2}):(\d{2}) ([+-]\d{4})$/);
  if (!parts) return new Date();

  const day = Number(parts[1]);
  const month = months[parts[2]] || 0;
  const year = Number(parts[3]);
  const hour = Number(parts[4]);
  const minute = Number(parts[5]);
  const second = Number(parts[6]);
  return new Date(Date.UTC(year, month, day, hour, minute, second));
}

function countBy(entries, key) {
  return entries.reduce((map, entry) => {
    const value = entry[key] || "inconnu";
    map[value] = (map[value] || 0) + 1;
    return map;
  }, {});
}

function topEntries(map, limit) {
  return Object.entries(map)
    .sort((a, b) => b[1] - a[1])
    .slice(0, limit);
}

function renderStatus(entries, invalidCount) {
  statusPanel.classList.remove("hidden");
  statusPanel.innerHTML = `
    <p class="status-line"><strong>${entries.length}</strong> requêtes analysées.</p>
    <p class="status-line">${invalidCount} ligne(s) non reconnue(s).</p>
  `;
}

function renderSummary(entries) {
  summary.classList.remove("hidden");
  tablesContainer.classList.remove("hidden");
  statsContainer.innerHTML = `
    <p>Total requêtes : <strong>${entries.length}</strong></p>
    <p>IP uniques : <strong>${new Set(entries.map(e => e.ip)).size}</strong></p>
    <p>URL uniques : <strong>${new Set(entries.map(e => e.url)).size}</strong></p>
    <p>Agents uniques : <strong>${new Set(entries.map(e => e.agent)).size}</strong></p>
  `;
}

function renderThreats(entries) {
  threatsPanel.classList.remove("hidden");

  const results = [
    { name: "Scan", result: detectScan(entries) },
    { name: "SQL Injection", result: detectSqlInjection(entries) },
    { name: "Brute Force", result: detectBruteForce(entries) },
    { name: "DDoS", result: detectDDoS(entries) }
  ];

  threatTable.innerHTML = `
    <tr><th>Détecteur</th><th>Statut</th><th>Détails</th></tr>
    ${results.map(({ name, result }) => `<tr><td>${name}</td><td>${formatBadge(result.status)}</td><td>${result.details}</td></tr>`).join("")}
  `;
}

function renderTable(table, data, headers) {
  table.innerHTML = `
    <tr>${headers.map(h => `<th>${h}</th>`).join("")}</tr>
    ${data.map(row => `<tr>${row.map(cell => `<td>${cell}</td>`).join("")}</tr>`).join("")}
  `;
}

function renderTables(entries) {
  renderTable(topIpsTable, topEntries(countBy(entries, "ip"), 10), ["IP", "Nombre"]);
  renderTable(topUrlsTable, topEntries(countBy(entries, "url"), 10), ["URL", "Nombre"]);
  renderTable(topAgentsTable, topEntries(countBy(entries, "agent"), 5), ["User Agent", "Nombre"]);
  renderTable(httpCodesTable, topEntries(countBy(entries, "status"), 20), ["Code HTTP", "Occurrences"]);
}

function detectScan(entries) {
  const sensitivePaths = /.*(\/admin|\/wp-login\.php|\/\.env|\/phpmyadmin|\/config\.yml|\/\.git\/config|\/backup\.sql).*/i;
  const attackTools = /.*(sqlmap|nikto|nmap|dirbuster|gobuster).*/i;

  const foundPath = entries.some(e => sensitivePaths.test(String(e.url)));
  const foundTool = entries.some(e => attackTools.test(String(e.agent)));
  if (foundPath) {
    return { status: "CRITICAL", details: "Accès à des chemins sensibles ou d'administration." };
  }
  if (foundTool) {
    return { status: "CRITICAL", details: "User-Agent suspect détecté (outil d'attaque)." };
  }

  const urlsByIp = {};
  entries.forEach(e => {
    if (e.status === "404" && e.ip && e.url) {
      urlsByIp[e.ip] = urlsByIp[e.ip] || new Set();
      urlsByIp[e.ip].add(e.url);
    }
  });

  const scanIp = Object.keys(urlsByIp).find(ip => urlsByIp[ip].size > 20);
  if (scanIp) {
    return { status: "HIGH", details: `Plus de 20 URLs 404 distinctes détectées pour ${scanIp}.` };
  }

  return { status: "NONE", details: "Aucune activité de scan détectée." };
}

function detectSqlInjection(entries) {
  const sqlRegex = /.*(\'|%27|\"|%22|--|%2D%2D|\bUNION\b|\bSELECT\b|\bDROP\b|\bOR\b\s+1=1).*/i;
  const found = entries.some(e => sqlRegex.test(String(e.url)));
  if (found) {
    return { status: "HIGH", details: "Requête SQL suspecte détectée dans l'URL." };
  }
  return { status: "NONE", details: "Aucune injection SQL détectée." };
}

function detectBruteForce(entries) {
  const attemptsByIp = {};
  entries.forEach(e => {
    if (e.status === "401" || e.status === "403") {
      attemptsByIp[e.ip] = attemptsByIp[e.ip] || [];
      attemptsByIp[e.ip].push(e.timestamp.getTime() / 1000);
    }
  });

  let maxCount = 0;
  let suspectIp = "";
  Object.entries(attemptsByIp).forEach(([ip, times]) => {
    const count = maxWindowCount(times.sort((a,b) => a - b), 300);
    if (count > maxCount) {
      maxCount = count;
      suspectIp = ip;
    }
  });

  if (maxCount > 50) {
    return { status: "HIGH", details: `Plus de ${maxCount} échecs de connexion en 5 minutes pour ${suspectIp}.` };
  }
  if (maxCount > 10) {
    return { status: "MEDIUM", details: `Tentatives répétées détectées par ${suspectIp}.` };
  }
  return { status: "NONE", details: "Aucune brute force évidente détectée." };
}

function detectDDoS(entries) {
  if (entries.length === 0) {
    return { status: "NONE", details: "Aucune donnée pour l'analyse DDoS." };
  }

  const times = entries.map(e => e.timestamp.getTime() / 1000).sort((a,b) => a - b);
  const duration = Math.max(1, times[times.length - 1] - times[0]);
  const averageRps = entries.length / duration;
  const globalMax = maxWindowCount(times, 10);

  if (globalMax > averageRps * 50 * 10) {
    return { status: "CRITICAL", details: "Trafic global très élevé : possible DDoS distribué." };
  }

  const byIp = {};
  entries.forEach(e => {
    byIp[e.ip] = byIp[e.ip] || [];
    byIp[e.ip].push(e.timestamp.getTime() / 1000);
  });

  const ipSuspect = Object.entries(byIp).find(([, list]) => maxWindowCount(list.sort((a,b) => a - b), 10) > averageRps * 10 * 10);
  if (ipSuspect) {
    return { status: "HIGH", details: `IP suspecte détectée : ${ipSuspect[0]}.` };
  }

  return { status: "NONE", details: "Pas de pic DDoS détecté." };
}

function maxWindowCount(sortedTimes, windowSeconds) {
  let maxCount = 0;
  let start = 0;
  for (let end = 0; end < sortedTimes.length; end += 1) {
    while (sortedTimes[end] - sortedTimes[start] > windowSeconds) {
      start += 1;
    }
    maxCount = Math.max(maxCount, end - start + 1);
  }
  return maxCount;
}

function formatBadge(status) {
  const classes = {
    NONE: "badge-none",
    MEDIUM: "badge-medium",
    HIGH: "badge-high",
    CRITICAL: "badge-critical"
  };
  return `<span class="badge ${classes[status] || "badge-none"}">${status}</span>`;
}
