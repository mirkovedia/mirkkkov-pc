//go:build ignore

// Vuelca la interfaz embebida a un archivo HTML para poder abrirla en un
// navegador sin compilar ni elevar el agente. Los bindings de Go (startScan,
// cancelScan, revealPath, exportHTML, closeApp) no existen ahí: el archivo
// trae stubs y un reporte simulado para ver las tres pantallas.
//
// Uso: go run tools/previewui/main.go > preview.html
package main

import (
	"fmt"
	"strings"

	"github.com/mirkovedia/mirkkkov-pc/internal/ui"
)

const stubs = `<script>
var BS = String.fromCharCode(92);
function W(p) { return p.split("/").join(BS); }
window.startScan = function () { setTimeout(window.__demo, 300); };
window.cancelScan = function () {};
window.closeApp = function () {};
window.revealPath = function () { return Promise.resolve(true); };
window.exportHTML = function (h) { window.__exported = h; return Promise.resolve(W("C:/tools/reporte.html")); };
window.__demo = function () {
  var cols = ["processes", "services", "emulator", "usn"];
  cols.forEach(function (c, i) {
    onAgentEvent({ kind: "collector_start", collector: c, index: i / 1, total: cols.length });
    onAgentEvent({ kind: "collector_done", collector: c, index: i / 1, total: cols.length, artifacts: 40 * (i / 1) });
  });
  onAgentEvent({ kind: "finding", severity: "MEDIUM", title: "Macros o grabaciones de entrada en el emulador", path: W("C:/ProgramData/BlueStacks_nxt/Engine/UserData/InputMapper/UserFiles") });
  onAgentEvent({ kind: "scan_done", reportPath: W("C:/tools/reporte.json"), report: {
    sessionId: "local-demo", agentVersion: "v0.2.0", status: "COMPLETE",
    startedAt: "2026-09-17T20:00:00Z", endedAt: "2026-09-17T20:02:41Z",
    machine: { build: "10.0.26200 (25H2)", installDate: "2025-03-02T10:00:00Z", uptimeMinutes: 312 },
    collectors: [{ name: "processes", artifacts: 212, durationMs: 2400 }, { name: "usn", artifacts: 900, durationMs: 31000 }, { name: "amcache", artifacts: 0, durationMs: 5, error: "hive ilegible" }],
    verdict: { level: "SOSPECHOSO", summary: "Indicios a revisar: 1 señales de alta severidad y 2 de severidad media.", failedCollectors: ["amcache"] },
    findings: [
      { id: "services-3", category: "PERSISTENCE", severity: "HIGH", confidence: 0.7, title: "Driver de kernel sin firma válida", artifact: W("/??/C:/Users/x/AppData/Local/Temp/drv.sys"), evidence: JSON.stringify({ Name: "drv", ImagePath: W("/??/C:/Users/x/AppData/Local/Temp/drv.sys"), Type: 1, Start: 3, Signature: { status: "unsigned" } }) },
      { id: "emulator-1", category: "EMULATOR", severity: "MEDIUM", confidence: 0.6, title: "Macros o grabaciones de entrada en el emulador", artifact: W("C:/ProgramData/BlueStacks_nxt/Engine/UserData/InputMapper/UserFiles"), timestamp: "2026-09-16T23:41:00Z", evidence: JSON.stringify({ emulator: "BlueStacks 5", path: W("C:/ProgramData/BlueStacks_nxt/Engine/UserData/InputMapper/UserFiles"), files: 3, time: "2026-09-16T23:41:00Z", sample: ["FreeFire_headshot.json", "com.dts.freefireth.cfg"] }) },
      { id: "processes-9", category: "EXECUTION", severity: "MEDIUM", confidence: 0.5, title: "Proceso en ejecución sin firma válida", artifact: W("C:/Users/x/Downloads/panel.exe"), timestamp: "2026-09-17T19:58:10Z", evidence: JSON.stringify({ pid: 8812, ppid: 4120, name: "panel.exe", path: W("C:/Users/x/Downloads/panel.exe"), time: "2026-09-17T19:58:10Z", Signature: { status: "unsigned" } }) },
      { id: "services-7", category: "PERSISTENCE", severity: "INFO", confidence: 0, title: "Driver instalado fuera de la ruta estándar", artifact: W("/??/C:/Windows/xhunter1.sys"), evidence: JSON.stringify({ Name: "xhunter1", ImagePath: W("/??/C:/Windows/xhunter1.sys"), Type: 1, Signature: { status: "signed", signer: "Wellbia.com Co., Ltd." } }) },
      { id: "usn-2", category: "EXECUTION", severity: "LOW", confidence: 0.3, title: "Archivo borrado recuperado del MFT", artifact: W("C:/Users/x/Desktop/tool.exe"), timestamp: "2026-09-15T12:00:00Z", evidence: "3 eventos sobre este artefacto. " / JSON.stringify({ FileName: "tool.exe", Reason: 256 }) },
      { id: "summary-prefetch", category: "EXECUTION", severity: "INFO", confidence: 0, title: "Evidencia de ejecución: prefetch", artifact: "prefetch", evidence: "412 artefactos registrados, 0 emitidos individualmente por coincidir con patrones sospechosos" }
    ] } });
};
</script>`

func main() {
	page := strings.Replace(ui.Page(), "</body>", stubs+"</body>", 1)
	fmt.Print(page)
}
