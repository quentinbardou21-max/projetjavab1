const fileInput = document.getElementById("logFile");
const whitelistFileInput = document.getElementById("whitelistFile");
const analyseBtn = document.getElementById("analyseBtn");
const exportBtn = document.getElementById("exportBtn");
const statusPanel = document.getElementById("status");
const summary = document.getElementById("summary");
const statsContainer = document.getElementById("stats");
const securityPanel = document.getElementById("security");
const securityStats = document.getElementById("securityStats");
const threatsPanel = document.getElementById("threats");
const threatTable = document.getElementById("threatTable");
const blockingPanel = document.getElementById("blockingPanel");
const blockingRulesTable = document.getElementById("blockingRulesTable");
const tablesContainer = document.getElementById("tables");
const topIpsTable = document.getElementById("topIps");
const topUrlsTable = document.getElementById("topUrls");
const topAgentsTable = document.getElementById("topAgents");
const httpCodesTable = document.getElementById("httpCodes");

const SEVERITY_ORDER = {
  NONE: 0,
  MEDIUM: 1,
  HIGH: 2,
  CRITICAL: 3
};

let latestReportContent = "";
let latestWhitelistPreview = [];

analyseBtn.addEventListener("click", async () => {
  const logFile = fileInput.files[0];
  if (!logFile) {
    alert("Choisissez un fichier de logs.");
    return;
  }

  try {
    const whitelistFile = whitelistFileInput.files[0];
    const hasWhitelistFile = Boolean(whitelistFile);
    const whitelistFileName = hasWhitelistFile ? whitelistFile.name : "";
    const [logText, whitelistText] = await Promise.all([
      readFileAsText(logFile),
      whitelistFile ? readFileAsText(whitelistFile) : Promise.resolve("")
    ]);

    const lines = logText.split(/\r?\n/).filter((line) => line.trim());
    const { entries, invalidLines } = parseLogLines(lines);
    const whitelistSet = parseWhitelist(whitelistText);
    latestWhitelistPreview = [...whitelistSet].slice(0, 5);
    const matchedWhitelistCount = countWhitelistMatches(entries, whitelistSet);
    const ipProfiles = deriveIpProfiles(entries);
    const filteredProfiles = applyWhitelist(ipProfiles, whitelistSet);
    const blockingRules = buildBlockingRules(filteredProfiles);
    const excludedCount = matchedWhitelistCount;
    latestReportContent = buildReport(entries, filteredProfiles, blockingRules);
    exportBtn.disabled = false;

    renderStatus(entries, invalidLines, whitelistSet.size, excludedCount, matchedWhitelistCount, hasWhitelistFile, whitelistFileName);
    renderSummary(entries);
    renderSecurityOverview(whitelistSet, filteredProfiles, blockingRules, excludedCount, matchedWhitelistCount);
    renderThreats(entries);
    renderBlockingRules(blockingRules);
    renderTables(entries);
  } catch (error) {
    console.error(error);
    exportBtn.disabled = true;
    latestReportContent = "";
    alert("Impossible de lire les fichiers sélectionnés.");
  }
});

exportBtn.addEventListener("click", () => {
  if (!latestReportContent) {
    alert("Lance une analyse avant d'exporter le rapport.");
    return;
  }

  const blob = new Blob([latestReportContent], { type: "text/plain;charset=utf-8" });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = `rapport_securite_${new Date().toISOString().replace(/[:.]/g, "-")}.txt`;
  document.body.appendChild(anchor);
  anchor.click();
  anchor.remove();
  URL.revokeObjectURL(url);
});

function readFileAsText(file) {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => {
      try {
        const buffer = reader.result;
        if (!(buffer instanceof ArrayBuffer)) {
          resolve(String(buffer || ""));
          return;
        }

        const bytes = new Uint8Array(buffer);
        resolve(decodeTextBytes(bytes));
      } catch (error) {
        reject(error);
      }
    };
    reader.onerror = () => reject(reader.error || new Error("Lecture impossible"));
    reader.readAsArrayBuffer(file);
  });
}

function decodeTextBytes(bytes) {
  if (bytes.length >= 2) {
    const b0 = bytes[0];
    const b1 = bytes[1];
    if (b0 === 0xff && b1 === 0xfe) {
      return new TextDecoder("utf-16le").decode(bytes);
    }
    if (b0 === 0xfe && b1 === 0xff) {
      // Convert UTF-16BE to UTF-16LE before decoding.
      const swapped = new Uint8Array(bytes.length);
      for (let i = 0; i + 1 < bytes.length; i += 2) {
        swapped[i] = bytes[i + 1];
        swapped[i + 1] = bytes[i];
      }
      return new TextDecoder("utf-16le").decode(swapped);
    }
  }

  // Try UTF-8 first, then UTF-16LE as fallback for files without BOM.
  const utf8 = new TextDecoder("utf-8", { fatal: false }).decode(bytes);
  const hasManyNulls = /\u0000/.test(utf8);
  if (!hasManyNulls) {
    return utf8;
  }
  return new TextDecoder("utf-16le", { fatal: false }).decode(bytes);
}

function parseLogLines(lines) {
  const regex = /^(\S+) \S+ (\S+) \[([^\]]+)\] "(\S+) (\S+) (\S+)" (\d{3}) (\d+|-) "(.*?)" "(.*?)"$/;
  const entries = [];
  let invalid = 0;

  lines.forEach((line) => {
    const match = line.match(regex);
    if (!match) {
      invalid += 1;
      return;
    }

    const timestamp = parseTimestamp(match[3]);
    entries.push({
      ip: normalizeIp(match[1]),
      user: match[2],
      timestamp,
      method: match[4],
      url: match[5],
      protocol: match[6],
      status: match[7],
      size: match[8] === "-" ? 0 : Number(match[8]),
      referer: match[9],
      agent: match[10],
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

function parseWhitelist(text) {
  if (!text) {
    return new Set();
  }

  const content = text
    .replace(/^\uFEFF/, "")
    .replace(/\u0000/g, "")
    .normalize("NFKC")
    .replace(/[\uFF0E\u2024\u3002]/g, ".");

  const ipRegex = /\b(?:\d{1,3}\.){3}\d{1,3}\b/g;
  const extracted = [];

  content.split(/\r?\n/).forEach((line) => {
    const cleanLine = line.trim();
    if (!cleanLine || cleanLine.startsWith("#")) {
      return;
    }

    const matches = cleanLine.match(ipRegex);
    if (!matches) {
      return;
    }

    matches.forEach((candidate) => {
      if (isValidIpv4(candidate)) {
        extracted.push(normalizeIp(candidate));
      }
    });
  });

  // Fallback: if nothing was extracted, also inspect commented lines and noisy separators.
  if (extracted.length === 0) {
    const looseRegex = /(\d{1,3})\D+(\d{1,3})\D+(\d{1,3})\D+(\d{1,3})/g;
    let match;
    while ((match = looseRegex.exec(content)) !== null) {
      const candidate = `${match[1]}.${match[2]}.${match[3]}.${match[4]}`;
      if (isValidIpv4(candidate)) {
        extracted.push(normalizeIp(candidate));
      }
    }
  }

  return new Set(extracted);
}

function isValidIpv4(value) {
  const parts = value.split(".");
  if (parts.length !== 4) {
    return false;
  }

  return parts.every((part) => {
    const num = Number(part);
    return Number.isInteger(num) && num >= 0 && num <= 255;
  });
}

function countSeverityValues(ipProfiles) {
  return Object.values(ipProfiles).reduce((acc, profile) => {
    const level = profile.severity || "NONE";
    acc[level] = (acc[level] || 0) + 1;
    return acc;
  }, { NONE: 0, MEDIUM: 0, HIGH: 0, CRITICAL: 0 });
}

function buildReport(entries, filteredProfiles, blockingRules) {
  const severity = countSeverityValues(filteredProfiles);
  const timeline = buildIncidentTimeline(entries);

  const lines = [];
  lines.push("=== 6. RESUME EXECUTIF ===");
  lines.push(`Nombres d'alertes HIGH: ${severity.HIGH}`);
  lines.push(`Nombres d'alertes MEDIUM: ${severity.MEDIUM}`);
  lines.push(`Nombres d'alertes CRITICAL: ${severity.CRITICAL}`);
  lines.push("");

  lines.push("=== 7. TIMELINE DES INCIDENTS ===");
  if (timeline.length === 0) {
    lines.push("Aucun incident detecte.");
  } else {
    timeline.forEach((item) => lines.push(item));
  }
  lines.push("");

  lines.push("=== 8. DETAILS PAR IP SUSPECTE ===");
  const ipEntries = Object.entries(filteredProfiles)
    .filter(([, profile]) => severityRank(profile.severity) >= severityRank("MEDIUM"))
    .sort((a, b) => severityRank(b[1].severity) - severityRank(a[1].severity) || a[0].localeCompare(b[0]));

  if (ipEntries.length === 0) {
    lines.push("Aucune IP suspecte detectee.");
  } else {
    ipEntries.forEach(([ip, profile]) => {
      lines.push(`IP: ${ip} (${profile.severity})`);
      if (profile.reasons.length === 0) {
        lines.push("  -> Aucune precision disponible.");
      } else {
        profile.reasons.forEach((reason) => lines.push(`  -> ${reason}`));
      }
    });
  }
  lines.push("");

  lines.push("=== 9. RECOMMANDATIONS ===");
  lines.push("- Brute-Force : bannir automatiquement les IPs apres plusieurs tentatives.");
  lines.push("- DDoS : activer une protection en amont et limiter le taux de requetes.");
  lines.push("- Injection SQL : filtrer les caracteres suspects et utiliser des requetes preparees.");
  lines.push("- Scan : bloquer les outils connus et proteger les chemins sensibles.");
  lines.push("");

  lines.push("=== 10. REGLES DE BLOCAGE ===");
  if (blockingRules.length === 0) {
    lines.push("Aucune regle a generer.");
  } else {
    blockingRules.forEach((rule) => lines.push(rule.command));
  }

  return `${lines.join("\n")}\n`;
}

function buildIncidentTimeline(entries) {
  const events = [];

  entries.forEach((entry) => {
    const url = String(entry.url || "");
    const agent = String(entry.agent || "");
    const status = String(entry.status || "");
    const timestamp = entry.timestamp instanceof Date && !Number.isNaN(entry.timestamp.getTime())
      ? entry.timestamp.toISOString()
      : "unknown-time";

    if (/('|%27|"|%22|--|%2D%2D|\bUNION\b|\bSELECT\b|\bDROP\b|\bOR\b\s+1=1)/i.test(url)) {
      events.push(`[HIGH] ${timestamp} IP: ${entry.ip} - Suspicion d'injection SQL (${url})`);
    }

    if (/(\/admin|\/wp-login\.php|\/\.env|\/phpmyadmin|\/config\.yml|\/\.git\/config|\/backup\.sql)/i.test(url) ||
      /(sqlmap|nikto|nmap|dirbuster|gobuster)/i.test(agent)) {
      events.push(`[CRITICAL] ${timestamp} IP: ${entry.ip} - Activite de scan suspecte`);
    }

    if (status === "401" || status === "403") {
      events.push(`[MEDIUM] ${timestamp} IP: ${entry.ip} - Echec d'authentification (${status})`);
    }
  });

  return events.slice(0, 300);
}

function countWhitelistMatches(entries, whitelistSet) {
  if (whitelistSet.size === 0) {
    return 0;
  }

  const uniqueIpsInLog = new Set(entries.map((entry) => normalizeIp(entry.ip)).filter(Boolean));
  let count = 0;
  whitelistSet.forEach((ip) => {
    if (uniqueIpsInLog.has(ip)) {
      count += 1;
    }
  });
  return count;
}

function normalizeIp(value) {
  return String(value || "").trim();
}

function renderStatus(entries, invalidCount, whitelistCount, excludedCount, matchedWhitelistCount, hasWhitelistFile, whitelistFileName) {
  statusPanel.classList.remove("hidden");
  const lines = [
    `<p class="status-line"><strong>${entries.length}</strong> requêtes analysées.</p>`,
    `<p class="status-line">${invalidCount} ligne(s) non reconnue(s).</p>`,
    `<p class="status-line">${whitelistCount} IP(s) chargée(s) dans la White list.</p>`,
    `<p class="status-line">${matchedWhitelistCount} IP(s) White list détectée(s) dans ce log.</p>`,
    `<p class="status-line">${excludedCount} IP(s) exclue(s) par la White list.</p>`
  ];

  if (hasWhitelistFile) {
    lines.push(`<p class="status-line">Fichier White list chargé: ${escapeHtml(whitelistFileName || "(sans nom)")}</p>`);
    lines.push(`<p class="status-line">Aperçu White list: ${escapeHtml(latestWhitelistPreview.join(", ") || "(aucune IP extraite)")}</p>`);
  }

  if (whitelistCount > 0) {
    const sample = [...new Set(entries.map((entry) => entry.ip).filter(Boolean))]
      .filter((ip) => isValidIpv4(ip))
      .slice(0, 5)
      .join(", ");
    lines.push(`<p class="status-line">Aperçu IP log: ${escapeHtml(sample || "(aucune IP)")}</p>`);
  }

  if (hasWhitelistFile && whitelistCount === 0) {
    lines.push('<p class="status-line">Attention: fichier White list chargé mais aucune IP valide détectée.</p>');
  }

  statusPanel.innerHTML = lines.join("");
}

function renderSecurityOverview(whitelistSet, ipProfiles, blockingRules, excludedCount, matchedWhitelistCount) {
  securityPanel.classList.remove("hidden");

  const values = Object.values(ipProfiles);
  const criticalCount = values.filter((profile) => profile.severity === "CRITICAL").length;
  const highCount = values.filter((profile) => profile.severity === "HIGH").length;
  const mediumCount = values.filter((profile) => profile.severity === "MEDIUM").length;

  securityStats.innerHTML = [
    statCard("Menaces critiques", criticalCount),
    statCard("Menaces élevées", highCount),
    statCard("Menaces modérées", mediumCount),
    statCard("Règles de blocage", blockingRules.length),
    statCard("IP White listées", whitelistSet.size),
    statCard("IP White list trouvées", matchedWhitelistCount),
    statCard("IP exclues (White list)", excludedCount),
    statCard("IP analysées", values.length)
  ].join("");
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


function renderSummary(entries) {
  summary.classList.remove("hidden");
  tablesContainer.classList.remove("hidden");
  statsContainer.innerHTML = [
    statCard("Total requêtes", entries.length),
    statCard("IP uniques", new Set(entries.map((entry) => entry.ip)).size),
    statCard("URL uniques", new Set(entries.map((entry) => entry.url)).size),
    statCard("Agents uniques", new Set(entries.map((entry) => entry.agent)).size)
  ].join("");
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
    ${results.map(({ name, result }) => `<tr><td>${escapeHtml(name)}</td><td>${formatBadge(result.status)}</td><td>${escapeHtml(result.details)}</td></tr>`).join("")}
  `;
}

function renderBlockingRules(blockingRules) {
  blockingPanel.classList.remove("hidden");
  if (blockingRules.length === 0) {
    blockingRulesTable.innerHTML = `
      <tr><th>IP</th><th>Sévérité</th><th>Règle</th></tr>
      <tr><td colspan="3">Aucune règle de blocage à générer.</td></tr>
    `;
    return;
  }

  const rows = blockingRules.map((rule) => [rule.ip, rule.severity, rule.command]);
  renderTable(blockingRulesTable, rows, ["IP", "Sévérité", "Règle"]);
}

function renderTable(table, data, headers) {
  table.innerHTML = `
    <tr>${headers.map((header) => `<th>${escapeHtml(header)}</th>`).join("")}</tr>
    ${data.map((row) => `<tr>${row.map((cell) => `<td>${escapeHtml(String(cell))}</td>`).join("")}</tr>`).join("")}
  `;
}

function renderTables(entries) {
  renderTable(topIpsTable, topEntries(countBy(entries, "ip"), 10), ["IP", "Nombre"]);
  renderTable(topUrlsTable, topEntries(countBy(entries, "url"), 10), ["URL", "Nombre"]);
  renderTable(topAgentsTable, topEntries(countBy(entries, "agent"), 5), ["User Agent", "Nombre"]);
  renderTable(httpCodesTable, topEntries(countBy(entries, "status"), 20), ["Code HTTP", "Occurrences"]);
}

function deriveIpProfiles(entries) {
  const profiles = {};
  const authFailuresByIp = {};
  const urls404ByIp = {};
  const timestampsByIp = {};
  const suspiciousPaths = /(\/admin|\/wp-login\.php|\/\.env|\/phpmyadmin|\/config\.yml|\/\.git\/config|\/backup\.sql)/i;
  const attackTools = /(sqlmap|nikto|nmap|dirbuster|gobuster)/i;
  const sqlRegex = /('|%27|"|%22|--|%2D%2D|\bUNION\b|\bSELECT\b|\bDROP\b|\bOR\b\s+1=1)/i;

  entries.forEach((entry) => {
    const ip = entry.ip || "";
    if (!ip) {
      return;
    }

    ensureProfile(profiles, ip);
    const profile = profiles[ip];
    const url = String(entry.url || "");
    const agent = String(entry.agent || "");

    if (suspiciousPaths.test(url) || attackTools.test(agent)) {
      elevateProfile(profile, "CRITICAL", "Accès à une ressource sensible ou outil d’attaque détecté.");
    }

    if (sqlRegex.test(url)) {
      elevateProfile(profile, "HIGH", "Requête ressemblant à une injection SQL.");
    }

    if (entry.status === "401" || entry.status === "403") {
      authFailuresByIp[ip] = (authFailuresByIp[ip] || 0) + 1;
    }

    if (entry.status === "404") {
      if (!urls404ByIp[ip]) {
        urls404ByIp[ip] = new Set();
      }
      urls404ByIp[ip].add(url);
    }

    if (entry.timestamp instanceof Date && !Number.isNaN(entry.timestamp.getTime())) {
      if (!timestampsByIp[ip]) {
        timestampsByIp[ip] = [];
      }
      timestampsByIp[ip].push(entry.timestamp.getTime() / 1000);
    }
  });

  Object.entries(authFailuresByIp).forEach(([ip, count]) => {
    if (count > 50) {
      elevateProfile(profiles[ip], "HIGH", `Plus de ${count} échecs d’authentification.`);
    } else if (count > 10) {
      elevateProfile(profiles[ip], "MEDIUM", `Tentatives d’accès répétées (${count}).`);
    }
  });

  Object.entries(urls404ByIp).forEach(([ip, urls]) => {
    if (urls.size > 20) {
      elevateProfile(profiles[ip], "HIGH", `Plus de ${urls.size} URLs 404 distinctes.`);
    }
  });

  Object.entries(timestampsByIp).forEach(([ip, times]) => {
    const sortedTimes = times.sort((a, b) => a - b);
    const burst = maxWindowCount(sortedTimes, 10);
    if (burst > 120) {
      elevateProfile(profiles[ip], "CRITICAL", `Pic de trafic très élevé (${burst} requêtes en 10 secondes).`);
    } else if (burst > 40) {
      elevateProfile(profiles[ip], "HIGH", `Pic de trafic élevé (${burst} requêtes en 10 secondes).`);
    }
  });

  return profiles;
}

function applyWhitelist(ipProfiles, whitelistSet) {
  const filtered = {};
  Object.entries(ipProfiles).forEach(([ip, profile]) => {
    if (!whitelistSet.has(normalizeIp(ip))) {
      filtered[ip] = profile;
    }
  });
  return filtered;
}

function buildBlockingRules(ipProfiles) {
  return Object.entries(ipProfiles)
    .filter(([, profile]) => severityRank(profile.severity) >= severityRank("HIGH"))
    .sort((a, b) => severityRank(b[1].severity) - severityRank(a[1].severity) || a[0].localeCompare(b[0]))
    .map(([ip, profile]) => ({
      ip,
      severity: profile.severity,
      command: `iptables -A INPUT -s ${ip} -j DROP`
    }));
}

function ensureProfile(profiles, ip) {
  if (!profiles[ip]) {
    profiles[ip] = {
      severity: "NONE",
      reasons: []
    };
  }
}

function elevateProfile(profile, severity, reason) {
  if (severityRank(severity) > severityRank(profile.severity)) {
    profile.severity = severity;
  }
  if (reason && !profile.reasons.includes(reason)) {
    profile.reasons.push(reason);
  }
}

function severityRank(severity) {
  return SEVERITY_ORDER[severity] || 0;
}

function statCard(label, value) {
  return `
    <article class="stat-card">
      <h3>${escapeHtml(label)}</h3>
      <p>${escapeHtml(String(value))}</p>
    </article>
  `;
}

function escapeHtml(value) {
  return value
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

function detectScan(entries) {
  const sensitivePaths = /.*(\/admin|\/wp-login\.php|\/\.env|\/phpmyadmin|\/config\.yml|\/\.git\/config|\/backup\.sql).*/i;
  const attackTools = /.*(sqlmap|nikto|nmap|dirbuster|gobuster).*/i;

  const foundPath = entries.some((entry) => sensitivePaths.test(String(entry.url)));
  const foundTool = entries.some((entry) => attackTools.test(String(entry.agent)));
  if (foundPath) {
    return { status: "CRITICAL", details: "Accès à des chemins sensibles ou d'administration." };
  }
  if (foundTool) {
    return { status: "CRITICAL", details: "User-Agent suspect détecté (outil d'attaque)." };
  }

  const urlsByIp = {};
  entries.forEach((entry) => {
    if (entry.status === "404" && entry.ip && entry.url) {
      urlsByIp[entry.ip] = urlsByIp[entry.ip] || new Set();
      urlsByIp[entry.ip].add(entry.url);
    }
  });

  const scanIp = Object.keys(urlsByIp).find((ip) => urlsByIp[ip].size > 20);
  if (scanIp) {
    return { status: "HIGH", details: `Plus de 20 URLs 404 distinctes détectées pour ${scanIp}.` };
  }

  return { status: "NONE", details: "Aucune activité de scan détectée." };
}

function detectSqlInjection(entries) {
  const sqlRegex = /.*(\'|%27|\"|%22|--|%2D%2D|\bUNION\b|\bSELECT\b|\bDROP\b|\bOR\b\s+1=1).*/i;
  const found = entries.some((entry) => sqlRegex.test(String(entry.url)));
  if (found) {
    return { status: "HIGH", details: "Requête SQL suspecte détectée dans l'URL." };
  }
  return { status: "NONE", details: "Aucune injection SQL détectée." };
}

function detectBruteForce(entries) {
  const attemptsByIp = {};
  entries.forEach((entry) => {
    if (entry.status === "401" || entry.status === "403") {
      attemptsByIp[entry.ip] = attemptsByIp[entry.ip] || [];
      attemptsByIp[entry.ip].push(entry.timestamp.getTime() / 1000);
    }
  });

  let maxCount = 0;
  let suspectIp = "";
  Object.entries(attemptsByIp).forEach(([ip, times]) => {
    const count = maxWindowCount(times.sort((a, b) => a - b), 300);
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

  const times = entries.map((entry) => entry.timestamp.getTime() / 1000).sort((a, b) => a - b);
  const duration = Math.max(1, times[times.length - 1] - times[0]);
  const averageRps = entries.length / duration;
  const globalMax = maxWindowCount(times, 10);

  if (globalMax > averageRps * 50 * 10) {
    return { status: "CRITICAL", details: "Trafic global très élevé : possible DDoS distribué." };
  }

  const byIp = {};
  entries.forEach((entry) => {
    byIp[entry.ip] = byIp[entry.ip] || [];
    byIp[entry.ip].push(entry.timestamp.getTime() / 1000);
  });

  const ipSuspect = Object.entries(byIp).find(([, list]) => maxWindowCount(list.sort((a, b) => a - b), 10) > averageRps * 10 * 10);
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
  return `<span class="badge ${classes[status] || "badge-none"}">${escapeHtml(status)}</span>`;
}
