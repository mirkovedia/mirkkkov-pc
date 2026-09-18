//go:build ignore

// Vuelca la interfaz embebida a un archivo HTML para poder abrirla en un
// navegador sin compilar ni elevar el agente. Los bindings de Go (startScan,
// cancelScan, revealPath, exportHTML, closeApp) no existen ahí: el archivo
// trae stubs y datos simulados para ver las tres pantallas.
//
// Uso: go run tools/previewui/main.go > preview.html
//
// El hash de la URL elige la pantalla:
//
//	preview.html            consentimiento
//	preview.html#scan       revisión a mitad de camino
//	preview.html#results    resultado con indicios
//	preview.html#limpio     resultado limpio
//
// Agregar ",static" (preview.html#results,static) congela las animaciones,
// para capturas en modo headless.
package main

import (
	"fmt"
	"strings"

	"github.com/mirkovedia/mirkkkov-pc/internal/ui"
)

// El JS del stub no usa barras invertidas: las rutas de Windows se escriben
// con "/" y W() las convierte, para no pelear con el escapado.
const stubs = `<script>
var BS = String.fromCharCode(92);
function W(p) { return p.split("/").join(BS); }

window.cancelScan = function () {};
window.closeApp = function () {};
window.revealPath = function () { return Promise.resolve(true); };
window.exportHTML = function (h) { window.__exported = h; return Promise.resolve(W("C:/tools/reporte.html")); };

var HOUR = 3600000;
var NOW = Math.floor(Date.now() / HOUR) * HOUR;
var FROM = NOW - 719 * HOUR;

// Generador determinista: la misma vista previa en cada corrida.
var seed = 7;
function rnd() { seed = (seed * 16807) % 2147483647; return seed / 2147483647; }

// mockActivity imita una PC de jugador: prendida de tarde y de noche, algunos
// dias apagada, y una rafaga de borrados poco antes de la revision.
function mockActivity(burst) {
  var ex = [], fi = [], se = [];
  for (var i = 0; i < 720; i++) {
    var d = new Date(FROM + i * HOUR);
    var h = d.getHours();
    var day = Math.floor(i / 24);
    var off = day % 9 === 4 || day % 13 === 7;
    var on = !off && (h >= 15 || h <= 1);
    ex.push(on ? Math.round(rnd() * rnd() * 40) : 0);
    fi.push(on ? Math.round(rnd() * rnd() * rnd() * 90) : (rnd() > .97 ? 2 : 0));
    se.push(on && (h === 15 || (h === 1 && rnd() > .4)) ? 1 + Math.round(rnd() * 2) : 0);
  }
  if (burst) { fi[718] += 140; fi[719] += 260; ex[719] += 12; se[719] += 1; }
  return { from: new Date(FROM).toISOString(), bucketMinutes: 60, channels: { execution: ex, files: fi, session: se } };
}
function only(act, key) {
  var z = []; for (var i = 0; i < 720; i++) z.push(0);
  var ch = { execution: z, files: z, session: z };
  ch[key] = act.channels[key];
  return { from: act.from, bucketMinutes: 60, channels: ch };
}
function iso(hoursAgo) { return new Date(Date.now() - hoursAgo * HOUR).toISOString(); }

var SOURCES = ["processes", "bam", "shimcache", "amcache", "services", "persistence", "emulator", "sysconfig",
  "prefetch", "usn", "mft_timestomp", "deleted_entries", "scheduled_tasks", "eventlog"];

function reportWith(level, summary, findings, burst, failed) {
  return { kind: "scan_done", reportPath: W("C:/tools/reporte.json"), report: {
    sessionId: "local-9f2c41d07ab3e655", agentVersion: "v0.2.0", status: "COMPLETE",
    startedAt: iso(0.05), endedAt: iso(0.0458),
    machine: { build: "10.0.26200 (25H2)", installDate: "2025-03-02T10:00:00Z", uptimeMinutes: 312 },
    collectors: SOURCES.map(function (s) { return { name: s, artifacts: 40, durationMs: 300, error: failed && s === "amcache" ? "hive ilegible" : undefined }; }),
    verdict: { level: level, summary: summary, failedCollectors: failed ? ["amcache"] : [] },
    activity: mockActivity(burst), findings: findings } };
}

var FINDINGS = [
  { id: "services-3", category: "PERSISTENCE", severity: "HIGH", confidence: 0.7, title: "Driver de kernel sin firma válida", artifact: W("/??/C:/Users/x/AppData/Local/Temp/drv.sys"), evidence: JSON.stringify({ Name: "drv", ImagePath: W("/??/C:/Users/x/AppData/Local/Temp/drv.sys"), Type: 1, Start: 3, Signature: { status: "unsigned" } }) },
  { id: "deleted-1", category: "ANTI_FORENSIC", severity: "MEDIUM", confidence: 0.8, title: "Archivo borrado recuperado del MFT", artifact: W("C:/Users/x/Desktop/ff_loader_v2.exe"), timestamp: iso(0.4), evidence: JSON.stringify({ FileName: "ff_loader_v2.exe", FullPath: W("C:/Users/x/Desktop/ff_loader_v2.exe"), SI: { Created: iso(30), Modified: iso(0.5) }, Verdict: { Stomped: false } }) },
  { id: "emulator-1", category: "EMULATOR", severity: "MEDIUM", confidence: 0.6, title: "Macros o grabaciones de entrada en el emulador", artifact: W("C:/ProgramData/BlueStacks_nxt/Engine/UserData/InputMapper/UserFiles"), timestamp: iso(26), evidence: JSON.stringify({ emulator: "BlueStacks 5", path: W("C:/ProgramData/BlueStacks_nxt/Engine/UserData/InputMapper/UserFiles"), files: 3, time: iso(26), sample: ["FreeFire_headshot.json", "com.dts.freefireth.cfg"] }) },
  { id: "processes-9", category: "EXECUTION", severity: "LOW", confidence: 0.3, title: "Proceso en ejecución sin firma válida", artifact: W("C:/Users/x/Downloads/panel.exe"), timestamp: iso(1.2), evidence: JSON.stringify({ pid: 8812, ppid: 4120, name: "panel.exe", path: W("C:/Users/x/Downloads/panel.exe"), time: iso(1.2), Signature: { status: "unsigned" } }) },
  { id: "usn-2", category: "EXECUTION", severity: "LOW", confidence: 0.3, title: "Actividad sobre un archivo con nombre sospechoso", artifact: W("C:/Users/x/Desktop/tool.exe"), timestamp: iso(74), evidence: "3 eventos sobre este artefacto. " + JSON.stringify({ FileName: "tool.exe", Reason: 256 }) },
  { id: "services-7", category: "PERSISTENCE", severity: "INFO", confidence: 0, title: "Driver instalado fuera de la ruta estándar", artifact: W("/??/C:/Windows/xhunter1.sys"), evidence: JSON.stringify({ Name: "xhunter1", ImagePath: W("/??/C:/Windows/xhunter1.sys"), Type: 1, Signature: { status: "signed", signer: "Wellbia.com Co., Ltd." } }) },
  { id: "summary-prefetch", category: "EXECUTION", severity: "INFO", confidence: 0, title: "Evidencia de ejecución: prefetch", artifact: "prefetch", evidence: "412 artefactos registrados, 0 emitidos individualmente por coincidir con patrones sospechosos" }
];

function runSources(upTo, act) {
  for (var i = 0; i < upTo; i++) {
    var s = SOURCES[i];
    onAgentEvent({ kind: "collector_start", collector: s, index: i + 1, total: SOURCES.length });
    var part = s === "prefetch" || s === "bam" ? only(act, "execution") : s === "usn" ? only(act, "files") : s === "eventlog" ? only(act, "session") : null;
    onAgentEvent({ kind: "collector_done", collector: s, index: i + 1, total: SOURCES.length, artifacts: 30 + i * 47, activity: part || undefined });
  }
}

window.__scan = function () {
  show("screen-scan");
  document.getElementById("topbar-status").textContent = "Revisando";
  setScanning(true);
  var act = mockActivity(true);
  runSources(9, act);
  onAgentEvent({ kind: "collector_start", collector: "usn", index: 10, total: 14 });
  onAgentEvent({ kind: "collector_progress", collector: "usn", index: 10, total: 14, fraction: 0.63 });
  onAgentEvent({ kind: "finding", severity: "HIGH", title: FINDINGS[0].title, path: FINDINGS[0].artifact });
  onAgentEvent({ kind: "finding", severity: "MEDIUM", title: FINDINGS[2].title, path: FINDINGS[2].artifact, timestamp: iso(26) });
  onAgentEvent({ kind: "finding", severity: "LOW", title: FINDINGS[3].title, path: FINDINGS[3].artifact, timestamp: iso(1.2) });
};
window.__results = function () {
  onAgentEvent(reportWith("SOSPECHOSO", "Indicios a revisar: 1 señal de alta severidad y 2 de severidad media.", FINDINGS, true, true));
};
window.__limpio = function () {
  onAgentEvent(reportWith("LIMPIO", "Sin hallazgos relevantes.", FINDINGS.slice(3), false, false));
};
window.startScan = function () { window.__scan(); setTimeout(window.__results, 2500); };

// "#results,static" congela animaciones y transiciones: las capturas en
// modo headless no las avanzan y saldrian a medio camino.
var parts = (location.hash || "").replace("#", "").split(",");
if (parts.indexOf("static") !== -1) {
  var st = document.createElement("style");
  st.textContent = "*,*::before,*::after{animation:none!important;transition:none!important}";
  document.head.appendChild(st);
}
var route = parts[0];
if (route === "scan") window.__scan();
if (route === "results") window.__results();
if (route === "limpio") window.__limpio();
// "export" reemplaza la pagina por el HTML que se exportaria, para ver como
// queda el documento en papel.
if (parts.indexOf("export") !== -1) {
  onExportClick();
  setTimeout(function () { document.open(); document.write(window.__exported); document.close(); }, 50);
}
// Extras para capturas: "open" despliega los dos primeros hallazgos y
// "r48" / "r168" cambian el rango del registro.
if (parts.indexOf("open") !== -1) {
  var mains = document.querySelectorAll("#findings .finding-main");
  for (var k = 0; k < 2 && k < mains.length; k++) mains[k].click();
}
["48", "168"].forEach(function (r) {
  if (parts.indexOf("r" + r) !== -1) setRange(document.querySelector('.seg button[data-range="' + r + '"]'));
});
</script>`

func main() {
	page := strings.Replace(ui.Page(), "</body>", stubs+"</body>", 1)
	fmt.Print(page)
}
