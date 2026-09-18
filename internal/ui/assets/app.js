// Estado de la interfaz. El backend solo empuja eventos; toda la decisión de
// qué mostrar vive acá.
var state = {
  totalArtifacts: 0,
  collectors: {}, // nombre -> li del DOM
  live: { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 },
  report: null,
  reportPath: "",
  filters: { sev: { CRITICAL: true, HIGH: true, MEDIUM: true, LOW: true, INFO: true }, text: "", sort: "severity" },
  // Registro de actividad.
  activity: null,     // { from: ms, channels: {execution:[], files:[], session:[]} }
  range: 720,         // horas visibles
  markers: [],        // [{ t: ms, severity, title, id }]
  revealStrip: false, // descubrir el papel una sola vez
  findingEls: {},     // id del hallazgo -> su nodo
};

// Tope de nodos en el feed en vivo. Sin esto una revisión con muchas señales
// degrada el render: el DOM crece sin límite mientras el usuario mira.
var MAX_LIVE_NODES = 300;

var SEV_ORDER = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1, INFO: 0 };
var SEV_LIST = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"];
var SEV_LABEL = { CRITICAL: "Crítico", HIGH: "Alto", MEDIUM: "Medio", LOW: "Bajo", INFO: "Info" };

var CATEGORY_LABEL = {
  ANTI_FORENSIC: "Manipulación de rastros",
  PERSISTENCE: "Mecanismos de persistencia",
  EXECUTION: "Evidencia de ejecución",
  EMULATOR: "Emuladores y macros",
  KNOWN_CHEAT: "Cheats conocidos",
};

// Las fuentes se nombran por lo que la persona reconoce; el identificador
// técnico queda como dato secundario.
var COLLECTOR_LABEL = {
  processes: "Programas en ejecución",
  bam: "Actividad en segundo plano",
  shimcache: "Compatibilidad de programas",
  amcache: "Inventario de programas",
  services: "Servicios y drivers",
  persistence: "Inicio automático",
  emulator: "Emuladores y macros",
  sysconfig: "Configuración del sistema",
  prefetch: "Programas ejecutados",
  usn: "Diario de cambios de archivos",
  mft_timestomp: "Fechas de archivos",
  deleted_entries: "Archivos borrados",
  scheduled_tasks: "Tareas programadas",
  eventlog: "Registros de eventos",
};

var SIG_LABEL = { signed: "Firmado", unsigned: "Sin firma", invalid: "Firma inválida" };

var LEVEL_LABEL = {
  LIMPIO: "Sin hallazgos",
  INCOMPLETO: "Revisión parcial",
  SOSPECHOSO: "Indicios a revisar",
  EVIDENCIA_FUERTE: "Evidencia fuerte",
};

var FOLDER_ICON =
  '<svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.3" aria-hidden="true">' +
  '<path d="M1.5 4.2c0-.6.5-1.1 1.1-1.1h3.2l1.4 1.6h6.2c.6 0 1.1.5 1.1 1.1v6.4c0 .6-.5 1.1-1.1 1.1H2.6c-.6 0-1.1-.5-1.1-1.1z"/></svg>';

function collectorLabel(name) { return COLLECTOR_LABEL[name] || name; }

function show(id) {
  document.body.setAttribute("data-screen", id.replace("screen-", ""));
  document.getElementById("main").scrollTop = 0;
  renderStrip();
}

function acceptConsent() {
  show("screen-scan");
  document.getElementById("topbar-status").textContent = "Revisando";
  setScanning(true);
  window.startScan();
}

// setScanning enciende o apaga las señales de actividad. Van juntas a
// propósito: si una queda animando cuando la revisión terminó, la interfaz
// miente sobre lo que está pasando.
function setScanning(on) {
  document.body.classList.toggle("scanning", on);
  document.getElementById("wave").hidden = !on;
  document.getElementById("brand-dot").classList.toggle("live", on);
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

// onCancelClick pide al backend que corte la revisión. Lo ya revisado igual
// termina en el reporte, marcado como ABORTED: la pantalla de resultados
// llega sola cuando el backend suelta los recursos y escribe el archivo.
function onCancelClick() {
  var btn = document.getElementById("cancel-btn");
  btn.disabled = true;
  btn.textContent = "Cancelando…";
  document.getElementById("progress-current").textContent = "Deteniendo la revisión";
  window.cancelScan();
}

// ---------------------------------------------------------------- eventos

// Punto de entrada que el backend invoca por cada evento de la revisión.
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
  document.getElementById("progress-current").textContent = collectorLabel(ev.collector);
  document.getElementById("progress-count").textContent = ev.index + " / " + ev.total;

  var li = state.collectors[ev.collector];
  if (!li) {
    li = document.createElement("li");
    li.innerHTML =
      '<span class="c-icon"></span><span class="c-name"></span>' +
      '<span class="c-meta"></span><span class="c-track"><i class="c-fill"></i></span>';
    li.querySelector(".c-name").textContent = collectorLabel(ev.collector);
    li.title = ev.collector;
    document.getElementById("collector-list").appendChild(li);
    state.collectors[ev.collector] = li;
  }
  li.className = "running";
  li.querySelector(".c-icon").textContent = "›";
  li.querySelector(".c-meta").textContent = "";
  li.querySelector(".c-fill").style.width = "0%";
  li.scrollIntoView({ block: "nearest" });

  // La barra global arranca en lo ya completado y avanza dentro del tramo de
  // esta fuente a medida que llega su avance interno.
  setGlobalProgress(ev.index - 1, ev.total, 0);
}

// onCollectorProgress mueve la barra DENTRO de la fuente actual. Es lo que
// evita que se vea congelada durante los segundos que tarda la MFT.
function onCollectorProgress(ev) {
  var li = state.collectors[ev.collector];
  if (li) {
    var pct = Math.round((ev.fraction || 0) * 100);
    li.querySelector(".c-fill").style.width = pct + "%";
    li.querySelector(".c-meta").textContent = pct + "%";
  }
  setGlobalProgress(ev.index - 1, ev.total, ev.fraction || 0);
}

// setGlobalProgress compone el avance total: fuentes terminadas más la
// fracción de la que está corriendo.
function setGlobalProgress(completed, total, fraction) {
  if (!total) return;
  var pct = ((completed + fraction) / total) * 100;
  document.getElementById("progress-bar").style.width = pct + "%";
  document.getElementById("progress-pct").textContent = Math.round(pct) + "%";
}

function onCollectorDone(ev) {
  var li = state.collectors[ev.collector];
  if (li) {
    if (ev.error) {
      li.className = "failed";
      li.querySelector(".c-icon").textContent = "!";
      li.querySelector(".c-meta").textContent = "no se pudo leer";
      li.title = ev.collector + ": " + ev.error;
    } else {
      li.className = "done";
      li.querySelector(".c-icon").textContent = "✓";
      var n = ev.artifacts || 0;
      li.querySelector(".c-meta").textContent = n.toLocaleString("es");
      state.totalArtifacts += n;
    }
    li.querySelector(".c-fill").style.width = "100%";
  }
  setGlobalProgress(ev.index, ev.total, 0);
  countUp(document.getElementById("progress-artifacts-n"), state.totalArtifacts);

  // El registro se dibuja fuente por fuente, mientras la revisión corre.
  if (ev.activity) {
    mergeActivity(ev.activity);
    renderStrip();
  }
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
  item.className = "live-item";
  item.innerHTML =
    '<span class="badge sev-' + sev.toLowerCase() + '"></span>' +
    '<span class="live-title"></span>' +
    '<span class="live-path"></span>';
  item.querySelector(".badge").textContent = SEV_LABEL[sev] || sev;
  item.querySelector(".live-title").textContent = ev.title || "";
  item.querySelector(".live-path").textContent = ev.path || "";
  feed.insertBefore(item, feed.firstChild);

  // Podar el final: lo viejo ya se contabilizó en los contadores y va a
  // aparecer completo en la pantalla de resultados.
  while (feed.childNodes.length > MAX_LIVE_NODES) {
    feed.removeChild(feed.lastChild);
  }

  if (ev.timestamp) {
    state.markers.push({ t: new Date(ev.timestamp).getTime(), severity: sev, title: ev.title || "", id: null });
    scheduleStrip();
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
      el.title = SEV_LABEL[k];
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
  setScanning(false);
  document.getElementById("topbar-status").textContent = "Error";
  document.getElementById("verdict").className = "screen-verdict verdict level-incompleto";
  document.getElementById("verdict-level").textContent = "No se pudo revisar";
  document.getElementById("verdict-summary").textContent = "La revisión se interrumpió antes de producir un resultado.";
  var note = document.getElementById("verdict-note");
  note.textContent = ev.error || "";
  note.hidden = !ev.error;
  show("screen-results");
}

function onScanDone(ev) {
  setScanning(false);
  document.getElementById("topbar-status").textContent = "Revisión terminada";

  var rep = ev.report || {};
  state.report = rep;
  state.reportPath = ev.reportPath || "";
  var findings = rep.findings || [];

  // El reporte trae la actividad completa y los hallazgos definitivos:
  // reemplazan lo que se fue dibujando en vivo.
  if (rep.activity) {
    state.activity = null;
    mergeActivity(rep.activity);
  }
  state.markers = [];
  for (var i = 0; i < findings.length; i++) {
    var f = findings[i];
    if (f.timestamp && f.severity !== "INFO") {
      state.markers.push({ t: new Date(f.timestamp).getTime(), severity: f.severity, title: f.title || "", id: f.id });
    }
  }
  state.revealStrip = true;

  renderVerdict(rep.verdict || {}, rep.status);
  renderContext(rep);
  renderDistribution(findings);
  renderFilters(findings);
  renderFindings(findings);

  document.getElementById("report-path").textContent = state.reportPath;
  document.getElementById("copy-btn").hidden = !state.reportPath;
  show("screen-results");
}

// ---------------------------------------------------------------- registro

var LANES = [
  { key: "execution", label: "Ejecución", ink: "var(--ink-exec)" },
  { key: "files", label: "Archivos", ink: "var(--ink-files)" },
  { key: "session", label: "Sesión", ink: "var(--ink-session)" },
];
var STRIP = { h: 150, gutter: 92, right: 16, rail: 24, lane: 34, axis: 22 };
var HOUR = 3600000;
var SVGNS = "http://www.w3.org/2000/svg";

function svgEl(name, attrs, text) {
  var el = document.createElementNS(SVGNS, name);
  for (var k in attrs) el.setAttribute(k, attrs[k]);
  if (text !== undefined) el.textContent = text;
  return el;
}

// mergeActivity suma la actividad de una fuente a la acumulada. Todas las
// fuentes comparten origen y resolución, así que se suma índice a índice.
function mergeActivity(act) {
  if (!act || !act.channels) return;
  var fromMs = new Date(act.from).getTime();
  if (!state.activity) {
    state.activity = { from: fromMs, channels: { execution: [], files: [], session: [] } };
  }
  // Una revisión que cruza el cambio de hora desplaza el origen una posición.
  var shift = Math.round((fromMs - state.activity.from) / HOUR);
  for (var key in state.activity.channels) {
    var src = act.channels[key] || [];
    var dst = state.activity.channels[key];
    for (var i = 0; i < src.length; i++) {
      var j = i + shift;
      if (j < 0) continue;
      dst[j] = (dst[j] || 0) + src[i];
    }
  }
}

var stripTimer = null;
function scheduleStrip() {
  clearTimeout(stripTimer);
  stripTimer = setTimeout(renderStrip, 120);
}

function setRange(btn) {
  state.range = parseInt(btn.getAttribute("data-range"), 10);
  var all = btn.parentNode.querySelectorAll("button");
  for (var i = 0; i < all.length; i++) {
    all[i].classList.toggle("on", all[i] === btn);
    all[i].setAttribute("aria-pressed", all[i] === btn ? "true" : "false");
  }
  renderStrip();
}

// renderStrip dibuja el registro: tres carriles de tinta sobre papel, una
// marca por hora cuya altura es el logaritmo de lo que pasó en esa hora. Se
// redibuja entero cada vez: son unos cientos de nodos.
function renderStrip() {
  var paper = document.getElementById("paper");
  var svg = document.getElementById("strip");
  var w = paper.clientWidth;
  if (!w) return;
  var H = STRIP.h;
  svg.setAttribute("viewBox", "0 0 " + w + " " + H);
  svg.setAttribute("width", w);
  svg.setAttribute("height", H);
  while (svg.firstChild) svg.removeChild(svg.firstChild);

  var act = state.activity;
  var total = 720;
  var range = state.range;
  var start = total - range;
  var x0 = STRIP.gutter;
  var x1 = w - STRIP.right;
  var bw = (x1 - x0) / range;
  var top = STRIP.rail;
  var bottom = H - STRIP.axis;
  // Sin datos todavía, el origen se calcula desde ahora para poder dibujar
  // igual la cuadrícula y las fechas sobre el papel en blanco.
  var fromMs = act ? act.from : Math.floor(Date.now() / HOUR) * HOUR - (total - 1) * HOUR;

  svg.appendChild(svgEl("rect", { x: 0, y: 0, width: x0 - 8, height: H, "class": "s-gutter" }));

  // Cuadrícula de tiempo.
  var grid = svgEl("g", {});
  var dayIndex = 0;
  for (var i = start; i <= total; i++) {
    var d = new Date(fromMs + i * HOUR);
    var x = x0 + (i - start) * bw;
    var hr = d.getHours();
    if (hr === 0) {
      grid.appendChild(svgEl("line", { x1: x, y1: top - 6, x2: x, y2: bottom, "class": "s-day" }));
      var labelEvery = range === 720 ? 5 : 1;
      if (dayIndex % labelEvery === 0 && x < x1 - 40) {
        var txt = range === 720
          ? d.toLocaleDateString("es", { day: "numeric", month: "short" })
          : d.toLocaleDateString("es", { weekday: "short", day: "numeric" });
        grid.appendChild(svgEl("text", { x: x + 4, y: H - 7, "class": "s-axis" }, txt));
      }
      dayIndex++;
    } else if (range === 48 && hr % 6 === 0) {
      grid.appendChild(svgEl("line", { x1: x, y1: top, x2: x, y2: bottom, "class": "s-grid" }));
      grid.appendChild(svgEl("text", { x: x + 4, y: H - 7, "class": "s-axis" }, (hr < 10 ? "0" : "") + hr + ":00"));
    } else if (range === 168 && hr === 12) {
      grid.appendChild(svgEl("line", { x1: x, y1: top, x2: x, y2: bottom, "class": "s-grid" }));
    }
  }
  svg.appendChild(grid);

  // Carriles.
  var ink = svgEl("g", {});
  var any = false;
  for (var l = 0; l < LANES.length; l++) {
    var lane = LANES[l];
    var base = top + (l + 1) * STRIP.lane - 3;
    svg.appendChild(svgEl("line", { x1: x0, y1: base + .5, x2: x1, y2: base + .5, "class": "s-base" }));
    var label = svgEl("text", { x: 12, y: base - 9, "class": "s-lane" }, lane.label);
    label.setAttribute("fill", lane.ink);
    svg.appendChild(label);

    var series = act ? act.channels[lane.key] || [] : [];
    var sum = 0;
    for (var b = start; b < total; b++) {
      var c = series[b] || 0;
      if (!c) continue;
      sum += c;
      var hgt = Math.min(STRIP.lane - 7, 3 + Math.log(c + 1) / Math.LN2 * 4.1);
      var bar = svgEl("rect", {
        x: (x0 + (b - start) * bw).toFixed(2), y: (base - hgt).toFixed(2),
        width: Math.max(1, bw - (bw > 3 ? 1 : 0)).toFixed(2), height: hgt.toFixed(2),
      });
      bar.setAttribute("fill", lane.ink);
      ink.appendChild(bar);
    }
    if (sum) any = true;
    if (act) {
      svg.appendChild(svgEl("text", { x: 12, y: base + 3, "class": "s-count" }, sum.toLocaleString("es")));
    }
  }
  svg.appendChild(ink);

  // Marcas de hallazgos sobre el riel superior.
  var rail = svgEl("g", {});
  for (var m = 0; m < state.markers.length; m++) {
    var mk = state.markers[m];
    var mx = x0 + ((mk.t - fromMs) / HOUR - start) * bw;
    if (mx < x0 || mx > x1) continue;
    var color = "var(--sev-" + mk.severity.toLowerCase() + ")";
    var drop = svgEl("line", { x1: mx, y1: 16, x2: mx, y2: bottom, "class": "s-drop" });
    drop.setAttribute("stroke", color);
    rail.appendChild(drop);
    var g = svgEl("g", { "class": "s-marker" });
    var tri = svgEl("path", { d: "M" + (mx - 5) + " 5 L" + (mx + 5) + " 5 L" + mx + " 16 Z" });
    tri.setAttribute("fill", color);
    g.appendChild(tri);
    g.appendChild(svgEl("title", {}, (SEV_LABEL[mk.severity] || mk.severity) + " · " + mk.title + " · " + fmtDateTime(mk.t)));
    if (mk.id) {
      g.setAttribute("tabindex", "0");
      g.setAttribute("role", "button");
      g.setAttribute("aria-label", "Ir al hallazgo: " + mk.title);
      (function (id) {
        g.addEventListener("click", function () { jumpToFinding(id); });
        g.addEventListener("keydown", function (e) {
          if (e.key === "Enter" || e.key === " ") { e.preventDefault(); jumpToFinding(id); }
        });
      })(mk.id);
    }
    rail.appendChild(g);
  }

  // Descubrir el papel de izquierda a derecha, una sola vez.
  if (state.revealStrip && document.body.getAttribute("data-screen") === "results") {
    state.revealStrip = false;
    svg.appendChild(svgEl("rect", { x: x0, y: 0, width: x1 - x0 + 1, height: bottom + 1, "class": "s-cover reveal" }));
  }
  svg.appendChild(rail);

  // Ahora.
  svg.appendChild(svgEl("line", { x1: x1, y1: 0, x2: x1, y2: bottom, "class": "s-now" }));
  svg.appendChild(svgEl("text", { x: x1 - 4, y: H - 7, "class": "s-now-label", "text-anchor": "end" }, "ahora"));

  var emptyEl = document.getElementById("paper-empty");
  if (document.body.getAttribute("data-screen") === "consent") {
    emptyEl.hidden = false;
  } else if (act && !any && !document.body.classList.contains("scanning")) {
    emptyEl.textContent = "Ninguna fuente aportó actividad con fecha en este rango.";
    emptyEl.hidden = false;
  } else {
    emptyEl.hidden = true;
  }
}

// jumpToFinding lleva del registro al hallazgo: limpia los filtros si lo
// estaban ocultando, abre su grupo y lo despliega.
function jumpToFinding(id) {
  var el = state.findingEls[id];
  if (!el || !document.body.contains(el)) {
    state.filters.text = "";
    document.getElementById("search").value = "";
    for (var k in state.filters.sev) state.filters.sev[k] = true;
    renderFilters(state.report.findings || []);
    renderFindings(state.report.findings || []);
    el = state.findingEls[id];
  }
  if (!el) return;
  var group = el.closest(".group");
  if (group) group.classList.add("open");
  if (!el.classList.contains("open")) el.querySelector(".finding-main").click();
  el.scrollIntoView({ block: "center", behavior: "smooth" });
  el.classList.remove("flash");
  void el.offsetWidth;
  el.classList.add("flash");
}

window.addEventListener("resize", scheduleStrip);

// ---------------------------------------------------------------- veredicto

function renderVerdict(verdict, status) {
  var level = verdict.level || "LIMPIO";
  document.getElementById("verdict").className = "screen-verdict verdict level-" + level.toLowerCase();
  document.getElementById("verdict-level").textContent = LEVEL_LABEL[level] || level;
  document.getElementById("verdict-summary").textContent = verdictSentence(level, verdict);

  var notes = [];
  if (status === "ABORTED") {
    notes.push("La revisión se detuvo antes de terminar. Este resultado cubre solo lo revisado hasta ese momento.");
  }
  if (verdict.failedCollectors && verdict.failedCollectors.length) {
    var names = [];
    for (var i = 0; i < verdict.failedCollectors.length; i++) names.push(collectorLabel(verdict.failedCollectors[i]));
    notes.push("No se pudo leer: " + names.join(", ") + ". Lo que esas fuentes hubieran mostrado no está en este resultado.");
  }
  var noteEl = document.getElementById("verdict-note");
  noteEl.textContent = notes.join(" ");
  noteEl.hidden = notes.length === 0;
}

function plural(n, one, many) { return n + " " + (n === 1 ? one : many); }

// verdictSentence dice en una oración lo que el titular no dice: cuánto hay
// y qué hacer con eso. El resumen que trae el reporte repite el nivel, que
// acá ya está escrito en grande justo arriba.
function verdictSentence(level, verdict) {
  var counts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0 };
  var findings = (state.report && state.report.findings) || [];
  for (var i = 0; i < findings.length; i++) {
    if (counts[findings[i].severity] !== undefined) counts[findings[i].severity]++;
  }
  switch (level) {
    case "LIMPIO":
      return "Ninguna fuente mostró señales de cheats, macros ni manipulación de rastros.";
    case "INCOMPLETO":
      return "No apareció nada para revisar, pero " +
        plural((verdict.failedCollectors || []).length, "fuente no se pudo leer", "fuentes no se pudieron leer") +
        ": el resultado no es concluyente.";
    case "SOSPECHOSO":
      return "Hay " + plural(counts.HIGH, "hallazgo de severidad alta", "hallazgos de severidad alta") + " y " +
        plural(counts.MEDIUM, "de severidad media", "de severidad media") + " para revisar con la persona.";
    case "EVIDENCIA_FUERTE":
      return "Hay " + plural(counts.CRITICAL, "hallazgo crítico", "hallazgos críticos") + " y " +
        plural(counts.HIGH, "de severidad alta", "de severidad alta") +
        ". Revisá la evidencia de cada uno antes de decidir.";
  }
  return verdict.summary || "";
}

// renderContext arma la ficha de la máquina: lo que hace falta para leer los
// hallazgos. Una instalación de hace tres días explica sola un registro casi
// vacío; un encendido de 4 minutos, una revisión hecha recién reiniciado.
function renderContext(rep) {
  var m = rep.machine || {};
  var rows = [];
  if (m.build) rows.push(["Windows", m.build]);
  if (m.installDate) rows.push(["Instalado", fmtDate(m.installDate)]);
  if (typeof m.uptimeMinutes === "number") rows.push(["Encendido hace", fmtMinutes(m.uptimeMinutes)]);
  if (m.vm) rows.push(["Entorno", "máquina virtual"]);
  var cols = rep.collectors || [];
  if (cols.length) {
    var failed = 0;
    for (var i = 0; i < cols.length; i++) if (cols[i].error) failed++;
    rows.push(["Fuentes leídas", (cols.length - failed) + " de " + cols.length]);
  }
  if (rep.startedAt && rep.endedAt) {
    var secs = Math.round((new Date(rep.endedAt) - new Date(rep.startedAt)) / 1000);
    if (secs > 0) rows.push(["Duración", fmtSeconds(secs)]);
  }
  if (rep.sessionId) rows.push(["Sesión", rep.sessionId]);
  if (rep.agentVersion) rows.push(["Agente", rep.agentVersion]);

  var dl = document.getElementById("context");
  dl.innerHTML = "";
  for (var r = 0; r < rows.length; r++) {
    var dt = document.createElement("dt");
    dt.textContent = rows[r][0];
    var dd = document.createElement("dd");
    dd.textContent = rows[r][1];
    dl.appendChild(dt);
    dl.appendChild(dd);
  }
}

function fmtDate(v) {
  var d = new Date(v);
  if (isNaN(d.getTime())) return String(v);
  return d.toLocaleDateString("es", { year: "numeric", month: "short", day: "numeric" });
}

function fmtDateTime(v) {
  var d = new Date(v);
  if (isNaN(d.getTime())) return String(v);
  return d.toLocaleString("es", { day: "numeric", month: "short", year: "numeric", hour: "2-digit", minute: "2-digit" });
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

// renderDistribution dibuja la proporción real de la evidencia. Un crítico
// entre 300 hallazgos se ve del tamaño que le corresponde, no como titular.
function renderDistribution(findings) {
  var counts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 };
  for (var i = 0; i < findings.length; i++) {
    if (counts[findings[i].severity] !== undefined) counts[findings[i].severity]++;
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
    seg.style.width = "0%";
    seg.style.background = color;
    bar.appendChild(seg);
    (function (node, pct) {
      setTimeout(function () { node.style.width = pct + "%"; }, 200);
    })(seg, (counts[k] / total) * 100);

    var item = document.createElement("span");
    item.className = "dist-item";
    item.innerHTML = '<span class="dist-swatch"></span><span class="dist-num"></span><span></span>';
    item.querySelector(".dist-swatch").style.background = color;
    item.querySelector(".dist-num").textContent = counts[k];
    item.querySelectorAll("span")[2].textContent = (SEV_LABEL[k] || k).toLowerCase();
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
    chip.querySelector(".chip-name").textContent = SEV_LABEL[k] || k;
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
  state.findingEls = {};
  var findings = [];
  for (var i = 0; i < all.length; i++) {
    if (passesFilters(all[i])) findings.push(all[i]);
  }
  document.getElementById("filter-count").textContent = findings.length === all.length
    ? all.length + (all.length === 1 ? " hallazgo" : " hallazgos")
    : findings.length + " de " + all.length;

  if (!all.length) {
    container.innerHTML = '<p class="empty">La revisión no registró ningún hallazgo.</p>';
    return;
  }
  if (!findings.length) {
    container.innerHTML = '<p class="empty">Ningún hallazgo coincide con el filtro. Probá con otra severidad o borrá la búsqueda.</p>';
    return;
  }

  container.innerHTML = "";
  if (state.filters.sort === "time") {
    container.appendChild(buildTimeline(findings));
    return;
  }

  var groups = {};
  for (var k = 0; k < findings.length; k++) {
    var cat = findings[k].category || "EXECUTION";
    if (!groups[cat]) groups[cat] = [];
    groups[cat].push(findings[k]);
  }
  // Las categorías se ordenan por su hallazgo más grave.
  var cats = Object.keys(groups);
  cats.sort(function (a, b) { return maxSeverity(groups[b]) - maxSeverity(groups[a]); });

  for (var c = 0; c < cats.length; c++) {
    var g = buildGroup(CATEGORY_LABEL[cats[c]] || cats[c], groups[cats[c]], true);
    g.style.animationDelay = (0.2 + c * 0.07).toFixed(2) + "s";
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

  var group = buildGroup("Línea de tiempo", [], false);
  group.classList.add("open");
  group.querySelector(".group-count").textContent = dated.length + " con fecha · " + undated.length + " sin fecha";
  var body = group.querySelector(".group-body");
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

function buildGroup(title, items, sortBySeverity) {
  if (sortBySeverity) {
    items.sort(function (a, b) { return (SEV_ORDER[b.severity] || 0) - (SEV_ORDER[a.severity] || 0); });
  }
  var group = document.createElement("div");
  group.className = "group";
  // Las categorías que solo tienen informativos arrancan cerradas: son ruido
  // para quien mira el resultado, pero siguen disponibles.
  if (maxSeverity(items) > SEV_ORDER.INFO) group.classList.add("open");

  var head = document.createElement("div");
  head.className = "group-head";
  head.setAttribute("role", "button");
  head.setAttribute("tabindex", "0");
  head.innerHTML = '<span class="group-caret">▶</span><span class="group-title"></span><span class="group-count"></span>';
  head.querySelector(".group-title").textContent = title;
  head.querySelector(".group-count").textContent = items.length + (items.length === 1 ? " hallazgo" : " hallazgos");
  head.onclick = function () { group.classList.toggle("open"); };
  head.onkeydown = function (e) {
    if (e.key === "Enter" || e.key === " ") { e.preventDefault(); group.classList.toggle("open"); }
  };

  var body = document.createElement("div");
  body.className = "group-body";
  for (var i = 0; i < items.length; i++) body.appendChild(buildFinding(items[i]));

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
// artefacto. ") del JSON del artefacto.
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
    // texto plano (resúmenes, errores de fuente): se muestra tal cual
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
  state.findingEls[f.id] = el;

  var sev = f.severity || "INFO";
  el.innerHTML =
    '<div class="finding-main">' +
    '<span class="badge sev-' + sev.toLowerCase() + '"></span>' +
    '<div class="f-body"><div class="finding-title"></div><div class="finding-path"></div></div>' +
    '<div class="f-side"></div>' +
    "</div>";
  el.querySelector(".badge").textContent = SEV_LABEL[sev] || sev;
  var titleEl = el.querySelector(".finding-title");
  var pathEl = el.querySelector(".finding-path");
  titleEl.textContent = f.title || "";
  pathEl.textContent = f.artifact || "";
  // Las filas de resumen y de fuente caída traen el identificador técnico
  // de la fuente: se muestran con el nombre que la persona reconoce y con su
  // texto como nota en prosa, no como ruta.
  var id = f.id || "";
  if (id.indexOf("summary-") === 0) {
    titleEl.textContent = collectorLabel(f.artifact) + ": actividad normal";
    pathEl.textContent = f.evidence || "";
    pathEl.classList.add("note");
  } else if (id.indexOf("collector-error-") === 0) {
    titleEl.textContent = "No se pudo leer: " + collectorLabel(f.artifact);
    pathEl.textContent = f.evidence || "";
    pathEl.classList.add("note");
  }

  var ev = parseEvidence(f.evidence);
  var side = el.querySelector(".f-side");
  if (f.timestamp) {
    var time = document.createElement("span");
    time.className = "f-time";
    time.textContent = fmtDateTime(f.timestamp);
    side.appendChild(time);
  }
  var sig = signatureOf(ev.data);
  if (sig) {
    var s = document.createElement("span");
    s.className = "sig sig-" + sig.status;
    s.textContent = SIG_LABEL[sig.status] + (sig.signer ? " · " + sig.signer : "");
    side.appendChild(s);
  }
  var metaParts = [];
  if (ev.count > 1) metaParts.push(ev.count + " eventos");
  if (typeof f.confidence === "number" && f.confidence > 0) metaParts.push("confianza " + Math.round(f.confidence * 100) + "%");
  if (metaParts.length) {
    var meta = document.createElement("span");
    meta.className = "f-meta";
    meta.textContent = metaParts.join(" · ");
    side.appendChild(meta);
  }

  // La evidencia se construye al primer clic. Con 400 hallazgos, renderizar
  // 400 tablas de entrada castigaría la pantalla de resultados.
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
    btn.innerHTML = FOLDER_ICON;
    btn.title = "Abrir la ubicación en el explorador";
    btn.setAttribute("aria-label", "Abrir la ubicación de " + (f.artifact || ""));
    btn.onclick = function () {
      // El backend valida de nuevo: el archivo puede haber sido borrado, en
      // cuyo caso abre el directorio que lo contenía.
      window.revealPath(f.artifact).then(function (ok) {
        if (!ok) {
          btn.title = "La ubicación ya no existe";
          toast("La ubicación ya no existe");
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
    toast(ok ? "Ruta copiada" : "No se pudo copiar la ruta");
  });
}

// onExportClick arma una copia estática de la pantalla de resultados, con
// toda la evidencia desplegada y sin controles, y se la pasa al backend para
// que la escriba junto al reporte. Es lo que se le manda a alguien que no va
// a abrir un JSON. Sale en papel: el mismo documento, con la paleta clara.
function onExportClick() {
  if (!state.report) return;
  // Desplegar toda la evidencia antes de clonar, para que el archivo sea
  // completo aunque nadie haya abierto nada.
  var all = state.report.findings || [];
  for (var i = 0; i < all.length; i++) {
    var node = state.findingEls[all[i].id];
    if (node) ensureEvidence(node, parseEvidence(all[i].evidence));
  }
  var root = document.documentElement.cloneNode(true);
  var drop = root.querySelectorAll("script, #screen-consent, #screen-scan, #statusbar, #toast, .results-actions, .reveal, .seg, .pen, .filter-bar, .s-cover");
  for (var d = 0; d < drop.length; d++) drop[d].remove();
  var body = root.querySelector("body");
  body.classList.add("exported");
  body.classList.remove("scanning");
  var stamp = document.createElement("p");
  stamp.className = "export-stamp";
  stamp.textContent = "Exportado el " + new Date().toLocaleString("es") + " desde " + state.reportPath +
    " · sesión " + (state.report.sessionId || "") + " · La versión firmada y verificable es el archivo JSON.";
  var main = root.querySelector("main");
  main.insertBefore(stamp, main.firstChild);
  window.exportHTML("<!DOCTYPE html>\n" + root.outerHTML).then(function (path) {
    toast(path ? "Exportado a " + path : "No se pudo exportar");
  });
}

// Primer dibujo: el papel en blanco, con su cuadrícula y sus fechas.
renderStrip();
