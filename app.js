const fileInput = document.getElementById("logFile");
const analyseBtn = document.getElementById("analyseBtn");
const summary = document.getElementById("summary");
const statsContainer = document.getElementById("stats");
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
    const entries = parseLogLines(lines);
    renderSummary(entries);
    renderTables(entries);
  };
  reader.readAsText(file, "UTF-8");
});

function parseLogLines(lines) {
  const regex = /^(\S+) \S+ (\S+) \[([^\]]+)\] "(\S+) (\S+) (\S+)" (\d{3}) (\d+|-) "(.*?)" "(.*?)"$/;
  return lines.map(line => {
    const m = line.match(regex);
    if (!m) return null;
    return {
      ip: m[1],
      user: m[2],
      method: m[4],
      url: m[5],
      protocol: m[6],
      status: m[7],
      size: m[8] === "-" ? 0 : Number(m[8]),
      referer: m[9],
      agent: m[10]
    };
  }).filter(entry => entry !== null);
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
  statsContainer.innerHTML = `
    <p>Total requêtes : <strong>${entries.length}</strong></p>
    <p>IP uniques : <strong>${new Set(entries.map(e => e.ip)).size}</strong></p>
    <p>URL uniques : <strong>${new Set(entries.map(e => e.url)).size}</strong></p>
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
