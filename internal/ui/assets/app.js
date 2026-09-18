// Estado de la interfaz. El backend solo empuja eventos; toda la decisión de
// qué mostrar vive acá.
var state = {
  totalArtifacts: 0,
  collectors: {}, // nombre -> li del DOM
  live: { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 },
  liveShown: 0,
  report: null,
  reportPath: "",
  filters: { sev: { CRITICAL: true, HIGH: true, MEDIUM: true, LOW: true, INFO: true }, text: "", sort: "severity" },
};

// Tope de nodos en el feed en vivo. Sin esto un escaneo con muchas señales
// degrada el render: el DOM crece sin límite mientras el usuario mira.
var MAX_LIVE_NODES = 300;

var SEV_ORDER = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1, INFO: 0 };
var SEV_LIST = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"];

var CATEGORY_LABEL = {
  ANTI_FORENSIC: "Manipulación de rastros",
  PERSISTENCE: "Mecanismos de persistencia",
  EXECUTION: "Evidencia de ejecución",
  EMULATOR: "Emuladores y macros",
  KNOWN_CHEAT: "Cheats conocidos",
};

var SIG_LABEL = {
  signed: "Firmado",
  unsigned: "Sin firma",
  invalid: "Firma inválida",
};

function show(id) {
  var screens = document.querySelectorAll(".screen");
  for (var i = 0; i < screens.length; i++) screens[i].classList.remove("active");
  document.getElementById(id).classList.add("active");
}

function acceptConsent() {
  show("screen-scan");
  document.getElementById("topbar-status").textContent = "Analizando";
  document.getElementById("statusbar").classList.add("on");
  setScanning(true);
  window.startScan();
}

// setScanning enciende o apaga las señales de actividad. Van juntas a
// propósito: si una queda animando cuando el escaneo terminó, la interfaz
// miente sobre lo que está pasando.
function setScanning(on) {
  document.getElementById("wave").hidden = !on;
  document.getElementById("brand-dot").classList.toggle("live", on);
  document.getElementById("sweep").classList.toggle("on", on);
  document.getElementById("statusbar").classList.toggle("on", on);
}

// countUp anima un número de su valor actual al nuevo. Un contador que salta
// de 0 a 1247 no se lee; uno que sube deja ver que algo está pasando.
function countUp(el, to) {
  var from = parseInt(el.getAttribute("data-v") || "0", 10);
  if (from === to) return;
  el.setAttribute("data-v", to);

  var dur = 420;
  var t0 = performance.now();
  function step(now) {
    var p = Math.min((now - t0) / dur, 1);
    // easing suave al final, para que se frene en vez de cortarse
    var eased = 1 - Math.pow(1 - p, 3);
    el.textContent = Math.round(from + (to - from) * eased).toLocaleString("es");
    if (p < 1) requestAnimationFrame(step);
  }
  requestAnimationFrame(step);
}

function rejectConsent() {
  window.closeApp();
}

// Los manejadores de botones NO pueden llamarse igual que las funciones que
// Go expone con Bind (closeApp, cancelScan, exportHTML): una declaración
// global "function closeApp" ES window.closeApp, pisa el binding y termina
// llamándose a sí misma hasta reventar la pila. El botón Cerrar estuvo roto
// por eso desde la Fase 6.
function onCloseClick() {
  window.closeApp();
}

// cancelScan pide al backend que corte el escaneo. Lo que ya se revisó igual
// termina en el reporte, marcado como ABORTED: la pantalla de resultados
// llega sola cuando el backend suelta los recursos y escribe el archivo.
function onCancelClick() {
  var btn = document.getElementById("cancel-btn");
  btn.disabled = true;
  btn.textContent = "Cancelando…";
  document.getElementById("progress-current").textContent = "Deteniendo el escaneo";
  window.cancelScan();
}

// ---------------------------------------------------------------- eventos

// Punto de entrada que el backend invoca por cada evento del escaneo.
window.onAgentEvent = function (ev) {
  switch (ev.kind) {
    case "collector_start":
      onCollectorStart(ev);
      break;
    case "collector_progress":
      onCollectorProgress(ev);
      break;
    case "collector_done":
      onCollectorDone(ev);
      break;
    case "finding":
      onFinding(ev);
      break;
    case "scan_done":
      onScanDone(ev);
      break;
    case "scan_error":
      onScanError(ev);
      break;
  }
};

function onCollectorStart(ev) {
  document.getElementById("progress-current").textContent = "Analizando " + ev.collector;
  document.getElementById("progress-count").textContent = ev.index + " / " + ev.total;

  var li = state.collectors[ev.collector];
  if (!li) {
    li = document.createElement("li");
    li.innerHTML =
      '<span class="c-icon">◐</span><span class="c-name"></span>' +
      '<span class="c-meta"></span><span class="c-track"><i class="c-fill"></i></span>';
    li.querySelector(".c-name").textContent = ev.collector;
    document.getElementById("collector-list").appendChild(li);
    state.collectors[ev.collector] = li;
  }
  li.className = "running";
  li.querySelector(".c-icon").textContent = "◐";
  li.querySelector(".c-meta").textContent = "";
  li.querySelector(".c-fill").style.width = "0%";

  // La barra global arranca en lo ya completado y avanza dentro del tramo de
  // este colector a medida que llega su avance interno.
  setGlobalProgress(ev.index - 1, ev.total, 0);
}

// onCollectorProgress mueve la barra DENTRO del colector actual. Es lo que
// evita que se vea congelada durante los 30-60 segundos que tarda la MFT.
function onCollectorProgress(ev) {
  var li = state.collectors[ev.collector];
  if (li) {
    var pct = Math.round((ev.fraction || 0) * 100);
    li.querySelector(".c-fill").style.width = pct + "%";
    li.querySelector(".c-meta").textContent = pct + "%";
  }
  setGlobalProgress(ev.index - 1, ev.total, ev.fraction || 0);
}

// setGlobalProgress compone el avance total: colectores terminados más la
// fracción del que está corriendo.
function setGlobalProgress(completed, total, fraction) {
  if (!total) return;
  var pct = ((completed + fraction) / total) * 100;
  document.getElementById("progress-bar").style.width = pct + "%";
  document.getElementById("progress-pct").textContent = Math.round(pct) + "%";
}

function onCollectorDone(ev) {
  var li = state.collectors[ev.collector];
  if (!li) return;

  if (ev.error) {
    li.className = "failed";
    li.querySelector(".c-icon").textContent = "!";
    li.querySelector(".c-meta").textContent = "no disponible";
    li.title = ev.error;
  } else {
    li.className = "done";
    li.querySelector(".c-icon").textContent = "✓";
    var n = ev.artifacts || 0;
    li.querySelector(".c-meta").textContent = n + (n === 1 ? " artefacto" : " artefactos");
    state.totalArtifacts += n;
  }
  li.querySelector(".c-fill").style.width = "100%";

  setGlobalProgress(ev.index, ev.total, 0);
  countUp(document.getElementById("progress-artifacts-n"), state.totalArtifacts);
}

// onFinding agrega una detección al feed en vivo. La severidad es preliminar:
// el backend todavía no aplicó combos ni deduplicación, así que la pantalla
// final puede mostrar un valor distinto.
function onFinding(ev) {
  var feed = document.getElementById("live-feed");
  var empty = document.getElementById("live-empty");
  if (empty) empty.remove();

  var sev = (ev.severity || "INFO").toUpperCase();
  if (state.live[sev] !== undefined) {
    state.live[sev]++;
    renderCounters(sev);
  }

  var item = document.createElement("div");
  item.className = "live-item lv-" + sev.toLowerCase();
  item.innerHTML =
    '<span class="badge sev-' + sev.toLowerCase() + '"></span>' +
    '<span class="live-title"></span>' +
    '<span class="live-path"></span>';
  item.querySelector(".badge").textContent = sev;
  item.querySelector(".live-title").textContent = ev.title || "";
  // La ruta se muestra en RTL por CSS para que, al recortarse, se vea el
  // nombre del archivo y no el prefijo C:\Windows\... que se repite siempre.
  item.querySelector(".live-path").textContent = ev.path || "";

  feed.insertBefore(item, feed.firstChild);
  state.liveShown++;

  // Podar el final: lo viejo ya se contabilizó en los contadores y va a
  // aparecer completo en la pantalla de resultados.
  while (feed.childNodes.length > MAX_LIVE_NODES) {
    feed.removeChild(feed.lastChild);
  }
}

function renderCounters(bumped) {
  var box = document.getElementById("live-counters");
  var order = ["CRITICAL", "HIGH", "MEDIUM", "LOW"];
  for (var i = 0; i < order.length; i++) {
    var k = order[i];
    var id = "counter-" + k;
    var el = document.getElementById(id);
    if (!el) {
      el = document.createElement("span");
      el.id = id;
      el.className = "counter sev-" + k.toLowerCase();
      box.appendChild(el);
    }
    countUp(el, state.live[k]);
    if (state.live[k] > 0) el.classList.add("on");
    if (k === bumped) {
      el.classList.remove("bump");
      void el.offsetWidth; // reinicia la animación
      el.classList.add("bump");
    }
  }
}

function onScanError(ev) {
  show("screen-results");
  setScanning(false);
  document.getElementById("topbar-status").textContent = "Error";
  var v = document.getElementById("verdict");
  v.className = "verdict level-incompleto";
  document.getElementById("verdict-level").textContent = "ERROR";
  document.getElementById("verdict-summary").textContent =
    "El escaneo no pudo completarse.";
  var note = document.getElementById("verdict-note");
  note.textContent = ev.error || "";
  note.hidden = !ev.error;
}

function onScanDone(ev) {
  show("screen-results");
  setScanning(false);
  document.getElementById("topbar-status").textContent = "Completado";

  var rep = ev.report || {};
  state.report = rep;
  state.reportPath = ev.reportPath || "";
  var verdict = rep.verdict || {};
  var findings = rep.findings || [];

  renderVerdict(verdict, rep.status);
  renderContext(rep);
  renderDistribution(findings);
  renderFilters(findings);
  renderFindings(findings);

  var pathEl = document.getElementById("report-path");
  pathEl.textContent = state.reportPath;
  document.getElementById("copy-btn").hidden = !state.reportPath;
}

// ---------------------------------------------------------------- render

function renderVerdict(verdict, status) {
  var level = verdict.level || "LIMPIO";
  var box = document.getElementById("verdict");
  box.className = "verdict level-" + level.toLowerCase();

  var LABEL = {
    LIMPIO: "SIN HALLAZGOS",
    INCOMPLETO: "REVISIÓN PARCIAL",
    SOSPECHOSO: "REQUIERE REVISIÓN",
    EVIDENCIA_FUERTE: "EVIDENCIA FUERTE",
  };
  var lvl = document.getElementById("verdict-level");
  lvl.textContent = LABEL[level] || level;
  // Reinicia la animación por si se vuelve a renderizar.
  lvl.classList.remove("reveal-type");
  void lvl.offsetWidth;
  lvl.classList.add("reveal-type");

  document.getElementById("verdict-summary").textContent = verdict.summary || "";

  var noteEl = document.getElementById("verdict-note");
  var notes = [];
  if (status === "ABORTED") {
    notes.push("El escaneo se detuvo antes de terminar. Este resultado cubre solo lo revisado hasta ese momento.");
  }
  if (verdict.failedCollectors && verdict.failedCollectors.length) {
    notes.push(
      "Revisión parcial: no se pudo leer " +
      verdict.failedCollectors.join(", ") +
      ". Lo que esa fuente hubiera mostrado no está en este resultado.");
  }
  noteEl.textContent = notes.join(" ");
  noteEl.hidden = notes.length === 0;
}

// renderContext arma la línea de contexto de la máquina: lo que hace falta
// para leer los hallazgos. Una instalación de hace tres días explica sola un
// Prefetch vacío; un uptime de 4 minutos, un escaneo hecho recién reiniciado.
function renderContext(rep) {
  var m = rep.machine || {};
  var parts = [];
  if (m.build) parts.push("Windows " + m.build);
  if (m.installDate) parts.push("instalado el " + fmtDate(m.installDate));
  if (typeof m.uptimeMinutes === "number") parts.push("encendido hace " + fmtMinutes(m.uptimeMinutes));
  if (m.vm) parts.push("máquina virtual");
  var cols = rep.collectors || [];
  if (cols.length) {
    var failed = 0;
    for (var i = 0; i < cols.length; i++) if (cols[i].error) failed++;
    parts.push((cols.length - failed) + " de " + cols.length + " fuentes leídas");
  }
  if (rep.startedAt && rep.endedAt) {
    var secs = Math.round((new Date(rep.endedAt) - new Date(rep.startedAt)) / 1000);
    if (secs > 0) parts.push("escaneo de " + fmtSeconds(secs));
  }
  if (rep.agentVersion) parts.push("agente " + rep.agentVersion);
  var el = document.getElementById("context");
  el.textContent = parts.join("  ·  ");
  el.hidden = parts.length === 0;
}

function fmtDate(iso) {
  var d = new Date(iso);
  if (isNaN(d.getTime())) return String(iso);
  return d.toLocaleDateString("es", { year: "numeric", month: "short", day: "numeric" });
}

function fmtDateTime(iso) {
  var d = new Date(iso);
  if (isNaN(d.getTime())) return String(iso);
  return d.toLocaleString("es", { year: "numeric", month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" });
}

function fmtMinutes(min) {
  if (min < 60) return min + " min";
  var h = Math.floor(min / 60);
  if (h < 48) return h + " h " + (min % 60) + " min";
  return Math.floor(h / 24) + " días";
}

function fmtSeconds(s) {
  if (s < 60) return s + " s";
  return Math.floor(s / 60) + " min " + (s % 60) + " s";
}

// renderDistribution dibuja la proporción real de la evidencia. Un CRITICAL
// entre 300 hallazgos se ve del tamaño que le corresponde, no como titular.
function renderDistribution(findings) {
  var counts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 };
  for (var i = 0; i < findings.length; i++) {
    var s = findings[i].severity;
    if (counts[s] !== undefined) counts[s]++;
  }

  var total = findings.length || 1;
  var bar = document.getElementById("dist-bar");
  var legend = document.getElementById("dist-legend");
  bar.innerHTML = "";
  legend.innerHTML = "";

  for (var j = 0; j < SEV_LIST.length; j++) {
    var k = SEV_LIST[j];
    if (!counts[k]) continue;
    var color = "var(--sev-" + k.toLowerCase() + ")";

    var seg = document.createElement("div");
    seg.className = "dist-seg";
    // Arranca en cero y crece: la proporción se "mide" en vez de aparecer ya
    // resuelta. El transition de .dist-seg hace el resto.
    seg.style.width = "0%";
    seg.style.background = color;
    seg.title = counts[k] + " " + k;
    bar.appendChild(seg);
    (function (node, pct) {
      setTimeout(function () { node.style.width = pct + "%"; }, 260);
    })(seg, (counts[k] / total) * 100);

    var item = document.createElement("span");
    item.className = "dist-item";
    item.innerHTML =
      '<span class="dist-swatch" style="background:' + color + '"></span>' +
      '<span class="dist-num"></span><span></span>';
    item.querySelector(".dist-num").textContent = counts[k];
    item.querySelectorAll("span")[2].textContent = k;
    legend.appendChild(item);
  }
}

// ---------------------------------------------------------------- filtros

function renderFilters(findings) {
  var counts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 };
  for (var i = 0; i < findings.length; i++) {
    if (counts[findings[i].severity] !== undefined) counts[findings[i].severity]++;
  }
  var box = document.getElementById("filter-chips");
  box.innerHTML = "";
  for (var j = 0; j < SEV_LIST.length; j++) {
    var k = SEV_LIST[j];
    var chip = document.createElement("button");
    chip.className = "chip sev-" + k.toLowerCase() + (state.filters.sev[k] ? " on" : "");
    chip.setAttribute("data-sev", k);
    chip.setAttribute("aria-pressed", state.filters.sev[k] ? "true" : "false");
    chip.innerHTML = '<span class="chip-name"></span><span class="chip-count"></span>';
    chip.querySelector(".chip-name").textContent = k;
    chip.querySelector(".chip-count").textContent = counts[k];
    chip.disabled = counts[k] === 0;
    chip.onclick = function () {
      var sev = this.getAttribute("data-sev");
      state.filters.sev[sev] = !state.filters.sev[sev];
      this.classList.toggle("on", state.filters.sev[sev]);
      this.setAttribute("aria-pressed", state.filters.sev[sev] ? "true" : "false");
      renderFindings(state.report.findings || []);
    };
    box.appendChild(chip);
  }
  document.getElementById("filter-bar").hidden = findings.length === 0;
}

var searchTimer = null;
function onSearchInput(el) {
  clearTimeout(searchTimer);
  searchTimer = setTimeout(function () {
    state.filters.text = (el.value || "").trim().toLowerCase();
    renderFindings(state.report.findings || []);
  }, 150);
}

function onSortChange(el) {
  state.filters.sort = el.value;
  renderFindings(state.report.findings || []);
}

function passesFilters(f) {
  if (!state.filters.sev[f.severity || "INFO"]) return false;
  var q = state.filters.text;
  if (!q) return true;
  var hay = ((f.title || "") + " " + (f.artifact || "") + " " + (f.evidence || "")).toLowerCase();
  return hay.indexOf(q) !== -1;
}

// ---------------------------------------------------------------- hallazgos

function renderFindings(all) {
  var container = document.getElementById("findings");
  var findings = [];
  for (var i = 0; i < all.length; i++) {
    if (passesFilters(all[i])) findings.push(all[i]);
  }
  var countEl = document.getElementById("filter-count");
  countEl.textContent = findings.length === all.length
    ? all.length + (all.length === 1 ? " hallazgo" : " hallazgos")
    : findings.length + " de " + all.length;

  if (!all.length) {
    container.innerHTML = '<div class="empty">No se registraron hallazgos.</div>';
    return;
  }
  if (!findings.length) {
    container.innerHTML = '<div class="empty">Ningún hallazgo coincide con el filtro.</div>';
    return;
  }

  container.innerHTML = "";
  if (state.filters.sort === "time") {
    container.appendChild(buildTimeline(findings));
    return;
  }

  // Agrupar por categoría.
  var groups = {};
  for (var k = 0; k < findings.length; k++) {
    var f = findings[k];
    var cat = f.category || "EXECUTION";
    if (!groups[cat]) groups[cat] = [];
    groups[cat].push(f);
  }

  // Ordenar categorías por su hallazgo más grave.
  var cats = Object.keys(groups);
  cats.sort(function (a, b) {
    return maxSeverity(groups[b]) - maxSeverity(groups[a]);
  });

  for (var c = 0; c < cats.length; c++) {
    var g = buildGroup(cats[c], groups[cats[c]]);
    // Escalonado: los grupos entran de a uno, el más grave primero.
    g.style.animationDelay = (0.28 + c * 0.09).toFixed(2) + "s";
    container.appendChild(g);
  }
}

// buildTimeline ordena por fecha del hecho, más reciente primero. Los
// hallazgos sin fecha van al final: no se inventa una.
function buildTimeline(findings) {
  var dated = [], undated = [];
  for (var i = 0; i < findings.length; i++) {
    (findings[i].timestamp ? dated : undated).push(findings[i]);
  }
  dated.sort(function (a, b) { return new Date(b.timestamp) - new Date(a.timestamp); });

  var group = document.createElement("div");
  group.className = "group open";
  var head = document.createElement("div");
  head.className = "group-head";
  head.innerHTML = '<span class="group-caret">▶</span><span class="group-title"></span><span class="group-count"></span>';
  head.querySelector(".group-title").textContent = "Línea de tiempo";
  head.querySelector(".group-count").textContent = dated.length + " con fecha, " + undated.length + " sin fecha";
  head.onclick = function () { group.classList.toggle("open"); };
  var body = document.createElement("div");
  body.className = "group-body";
  var lastDay = "";
  for (var j = 0; j < dated.length; j++) {
    var day = fmtDate(dated[j].timestamp);
    if (day !== lastDay) {
      var sep = document.createElement("div");
      sep.className = "day-sep";
      sep.textContent = day;
      body.appendChild(sep);
      lastDay = day;
    }
    body.appendChild(buildFinding(dated[j]));
  }
  if (undated.length) {
    var sep2 = document.createElement("div");
    sep2.className = "day-sep";
    sep2.textContent = "Sin fecha";
    body.appendChild(sep2);
    for (var u = 0; u < undated.length; u++) body.appendChild(buildFinding(undated[u]));
  }
  group.appendChild(head);
  group.appendChild(body);
  return group;
}

function maxSeverity(list) {
  var m = 0;
  for (var i = 0; i < list.length; i++) {
    var v = SEV_ORDER[list[i].severity] || 0;
    if (v > m) m = v;
  }
  return m;
}

function buildGroup(category, items) {
  items.sort(function (a, b) {
    return (SEV_ORDER[b.severity] || 0) - (SEV_ORDER[a.severity] || 0);
  });

  var group = document.createElement("div");
  group.className = "group";
  // Las categorías que solo tienen INFO arrancan colapsadas: son ruido para
  // quien mira el resultado, pero siguen disponibles.
  if (maxSeverity(items) > SEV_ORDER.INFO) group.classList.add("open");

  var head = document.createElement("div");
  head.className = "group-head";
  head.innerHTML =
    '<span class="group-caret">▶</span>' +
    '<span class="group-title"></span>' +
    '<span class="group-count"></span>';
  head.querySelector(".group-title").textContent = CATEGORY_LABEL[category] || category;
  head.querySelector(".group-count").textContent =
    items.length + (items.length === 1 ? " hallazgo" : " hallazgos");
  head.onclick = function () {
    group.classList.toggle("open");
  };

  var body = document.createElement("div");
  body.className = "group-body";
  for (var i = 0; i < items.length; i++) {
    body.appendChild(buildFinding(items[i]));
  }

  group.appendChild(head);
  group.appendChild(body);
  return group;
}

// revealable reproduce del lado del cliente la misma regla que ui.RevealablePath:
// solo las rutas reales del disco reciben botón de carpeta. Una tarea
// programada o un nombre de servicio no tienen ubicación que abrir.
function revealable(path) {
  if (!path) return false;
  if (path.indexOf("<sin-resolver>") !== -1) return false;
  if (/^[A-Za-z]:[\\/]/.test(path)) return true;
  return path.indexOf("\\\\") === 0;
}

// parseEvidence separa el prefijo de deduplicación ("N eventos sobre este
// artefacto. ") del JSON del artefacto. Devuelve {count, data} con data
// null si no es JSON.
function parseEvidence(evidence) {
  var out = { count: 0, data: null, raw: evidence || "" };
  var s = evidence || "";
  var m = /^(\d+) eventos sobre este artefacto\. ([\s\S]*)$/.exec(s);
  if (m) {
    out.count = parseInt(m[1], 10);
    s = m[2];
  }
  try {
    var parsed = JSON.parse(s);
    if (parsed && typeof parsed === "object") out.data = parsed;
  } catch (e) {
    // texto plano (resúmenes, errores de colector): se muestra tal cual
  }
  return out;
}

function signatureOf(data) {
  if (!data) return null;
  var sig = data.Signature || data.signature;
  if (!sig || !sig.status || sig.status === "unknown") return null;
  return sig;
}

function buildFinding(f) {
  var el = document.createElement("div");
  el.className = "finding";

  var sev = (f.severity || "INFO").toLowerCase();
  el.innerHTML =
    '<span class="badge sev-' + sev + '"></span>' +
    '<div class="finding-main">' +
    '<div class="finding-title"></div>' +
    '<div class="finding-path"></div>' +
    '<div class="finding-meta"></div>' +
    "</div>";

  el.querySelector(".badge").textContent = f.severity || "INFO";
  el.querySelector(".finding-title").textContent = f.title || "";
  el.querySelector(".finding-path").textContent = f.artifact || "";

  var ev = parseEvidence(f.evidence);
  var meta = el.querySelector(".finding-meta");
  var metaParts = [];
  if (f.timestamp) metaParts.push(fmtDateTime(f.timestamp));
  if (ev.count > 1) metaParts.push(ev.count + " eventos");
  if (typeof f.confidence === "number" && f.confidence > 0) metaParts.push("confianza " + Math.round(f.confidence * 100) + "%");
  meta.textContent = metaParts.join("  ·  ");
  var sig = signatureOf(ev.data);
  if (sig) {
    var badge = document.createElement("span");
    badge.className = "sig sig-" + sig.status;
    badge.textContent = SIG_LABEL[sig.status] + (sig.signer ? ": " + sig.signer : "");
    meta.appendChild(badge);
  }
  if (!meta.textContent) meta.hidden = true;

  // Evidencia expandible: se construye al primer clic. Con 400 hallazgos,
  // renderizar 400 tablas de entrada castigaría la pantalla de resultados.
  var main = el.querySelector(".finding-main");
  main.setAttribute("role", "button");
  main.setAttribute("tabindex", "0");
  main.setAttribute("aria-expanded", "false");
  function toggle() {
    var open = el.classList.toggle("open");
    main.setAttribute("aria-expanded", open ? "true" : "false");
    ensureEvidence(el, ev);
  }
  main.onclick = toggle;
  main.onkeydown = function (e) {
    if (e.key === "Enter" || e.key === " ") { e.preventDefault(); toggle(); }
  };

  if (revealable(f.artifact)) {
    var btn = document.createElement("button");
    btn.className = "reveal";
    btn.textContent = "\u{1F5C1}";
    btn.title = "Abrir la ubicación en el explorador";
    btn.setAttribute("aria-label", "Abrir la ubicación de " + (f.artifact || ""));
    btn.onclick = function (e) {
      e.stopPropagation();
      // El backend valida de nuevo: el archivo puede haber sido borrado, en
      // cuyo caso abre el directorio que lo contenía.
      window.revealPath(f.artifact).then(function (ok) {
        if (!ok) {
          btn.title = "La ubicación ya no existe";
          return;
        }
        btn.classList.add("done");
      });
    };
    el.appendChild(btn);
  }
  return el;
}

// ensureEvidence renderiza la tabla de evidencia una sola vez.
function ensureEvidence(el, ev) {
  if (el.querySelector(".finding-evidence")) return;
  var box = document.createElement("div");
  box.className = "finding-evidence";
  if (!ev.data) {
    var pre = document.createElement("pre");
    pre.textContent = ev.raw;
    box.appendChild(pre);
  } else {
    box.appendChild(evidenceTable(ev.data));
  }
  el.appendChild(box);
}

// evidenceTable convierte el objeto del artefacto en filas clave/valor. Los
// objetos anidados (SI, FN, Signature) se aplanan con prefijo.
function evidenceTable(data) {
  var table = document.createElement("table");
  var rows = flatten(data, "");
  for (var i = 0; i < rows.length; i++) {
    var tr = document.createElement("tr");
    var th = document.createElement("th");
    th.textContent = rows[i][0];
    var td = document.createElement("td");
    td.textContent = rows[i][1];
    tr.appendChild(th);
    tr.appendChild(td);
    table.appendChild(tr);
  }
  return table;
}

function flatten(obj, prefix) {
  var rows = [];
  var keys = Object.keys(obj);
  for (var i = 0; i < keys.length; i++) {
    var k = keys[i];
    var v = obj[k];
    var name = prefix ? prefix + "." + k : k;
    if (v === null || v === undefined || v === "") continue;
    if (Array.isArray(v)) {
      if (!v.length) continue;
      if (typeof v[0] === "object") {
        rows.push([name, v.length + " elementos"]);
      } else {
        rows.push([name, v.length > 8 ? v.slice(0, 8).join(", ") + " … (" + v.length + ")" : v.join(", ")]);
      }
    } else if (typeof v === "object") {
      rows = rows.concat(flatten(v, name));
    } else if (typeof v === "boolean") {
      rows.push([name, v ? "sí" : "no"]);
    } else if (typeof v === "string" && /^\d{4}-\d{2}-\d{2}T/.test(v)) {
      if (v.indexOf("0001-01-01") === 0) continue; // fecha cero de Go
      rows.push([name, fmtDateTime(v)]);
    } else {
      rows.push([name, String(v)]);
    }
  }
  return rows;
}

// ---------------------------------------------------------------- acciones

function toast(msg) {
  var el = document.getElementById("toast");
  el.textContent = msg;
  el.classList.add("on");
  clearTimeout(el._t);
  el._t = setTimeout(function () { el.classList.remove("on"); }, 2200);
}

// copyText intenta el portapapeles moderno y cae al comando clásico: la
// página vive en about:blank y no siempre cuenta como contexto seguro.
function copyText(text) {
  if (navigator.clipboard && navigator.clipboard.writeText) {
    return navigator.clipboard.writeText(text).then(function () { return true; }, function () { return legacyCopy(text); });
  }
  return Promise.resolve(legacyCopy(text));
}

function legacyCopy(text) {
  var ta = document.createElement("textarea");
  ta.value = text;
  ta.setAttribute("readonly", "");
  ta.style.position = "fixed";
  ta.style.opacity = "0";
  document.body.appendChild(ta);
  ta.select();
  var ok = false;
  try { ok = document.execCommand("copy"); } catch (e) { ok = false; }
  document.body.removeChild(ta);
  return ok;
}

function copyReportPath() {
  if (!state.reportPath) return;
  copyText(state.reportPath).then(function (ok) {
    toast(ok ? "Ruta copiada" : "No se pudo copiar");
  });
}

// exportHTML arma una copia estática de la pantalla de resultados, con toda
// la evidencia desplegada y sin controles, y se la pasa al backend para que
// la escriba junto al reporte. Es lo que se manda a alguien que no va a
// abrir un JSON.
function onExportClick() {
  if (!state.report) return;
  // Desplegar toda la evidencia antes de clonar, para que el archivo sea
  // completo aunque el usuario no haya abierto nada.
  var items = document.querySelectorAll("#findings .finding");
  for (var i = 0; i < items.length; i++) {
    if (!items[i].querySelector(".finding-evidence")) {
      items[i].querySelector(".finding-main").click();
      items[i].querySelector(".finding-main").click();
    }
  }
  var root = document.documentElement.cloneNode(true);
  var scripts = root.querySelectorAll("script");
  for (var s = 0; s < scripts.length; s++) scripts[s].remove();
  var drop = root.querySelectorAll("#screen-consent, #screen-scan, #statusbar, .results-actions, .reveal, #toast");
  for (var d = 0; d < drop.length; d++) drop[d].remove();
  root.querySelector("body").classList.add("exported");
  var stamp = document.createElement("div");
  stamp.className = "export-stamp";
  stamp.textContent = "Exportado el " + new Date().toLocaleString("es") + " desde " + state.reportPath +
    " · sesión " + (state.report.sessionId || "") + " · La versión firmada y verificable es el archivo JSON.";
  root.querySelector("#screen-results").insertBefore(stamp, root.querySelector("#screen-results").firstChild);
  var html = "<!DOCTYPE html>\n" + root.outerHTML;
  window.exportHTML(html).then(function (path) {
    toast(path ? "Exportado a " + path : "No se pudo exportar");
  });
}
