package verdict

import (
	"testing"
	"time"

	"github.com/mirkovedia/mirkkkov-pc/internal/collector"
	"github.com/mirkovedia/mirkkkov-pc/internal/report"
)

func TestEmulatorRules(t *testing.T) {
	if got := escalate(art("emulator.installed", `C:\Program Files\BlueStacks_nxt`, nil), ruleFor("emulator.installed")); got.Category != CatEmulator || got.Severity != SevInfo {
		t.Fatalf("installed = %+v", got)
	}
	if got := escalate(art("emulator.macro", `C:\ProgramData\BlueStacks_nxt\...\UserFiles`, nil), ruleFor("emulator.macro")); got.Severity != SevMedium {
		t.Fatalf("macro = %+v", got)
	}
	if got := escalate(art("macro_tool", `C:\Program Files\AutoHotkey`, map[string]string{"name": "AutoHotkey"}), ruleFor("macro_tool")); got.Severity != SevLow {
		t.Fatalf("AutoHotkey = %+v", got)
	}
	if got := escalate(art("macro_tool", `C:\Program Files\LGHUB`, map[string]string{"name": "Logitech G HUB", "weight": "info"}), ruleFor("macro_tool")); got.Severity != SevInfo {
		t.Fatalf("Logitech = %+v", got)
	}
}

func TestUnsignedAutorunInAppDataIsMedium(t *testing.T) {
	a := art("autorun", `C:\Users\x\AppData\Roaming\svc\ffloader.exe`, map[string]any{
		"path": `C:\Users\x\AppData\Roaming\svc\ffloader.exe`, "Signature": map[string]string{"Status": "unsigned"},
	})
	got := escalate(a, ruleFor("autorun"))
	// "loader" es marcador débil: escalateByName también aplica, con tope MEDIUM.
	if got.Severity != SevMedium {
		t.Fatalf("Severity = %s", got.Severity)
	}
	b := art("autorun", `C:\Program Files\Vendor\tool.exe`, map[string]any{
		"path": `C:\Program Files\Vendor\tool.exe`, "Signature": map[string]string{"Status": "unsigned"},
	})
	if got := escalate(b, ruleFor("autorun")); got.Severity != SevLow {
		t.Fatalf("sin firma en Program Files: Severity = %s, want LOW", got.Severity)
	}
	c := art("autorun", `C:\Users\x\AppData\Local\Discord\Update.exe`, map[string]any{
		"path": `C:\Users\x\AppData\Local\Discord\Update.exe`, "Signature": map[string]string{"Status": "signed"},
	})
	if got := escalate(c, ruleFor("autorun")); got.Severity != SevInfo {
		t.Fatalf("firmado: Severity = %s, want INFO", got.Severity)
	}
}

func TestUnsignedProcessRule(t *testing.T) {
	a := art("process", `C:\Users\x\Downloads\x.exe`, map[string]any{
		"path": `C:\Users\x\Downloads\x.exe`, "Signature": map[string]string{"Status": "unsigned"},
	})
	if got := escalate(a, ruleFor("process")); got.Severity != SevMedium {
		t.Fatalf("Severity = %s", got.Severity)
	}
	if titleOf(a) != "Proceso en ejecución sin firma válida" {
		t.Fatalf("title = %q", titleOf(a))
	}
	protected := art("process", "MsMpEng.exe", map[string]any{"name": "MsMpEng.exe", "Signature": map[string]string{"Status": "unknown"}})
	if got := escalate(protected, ruleFor("process")); got.Severity != SevInfo {
		t.Fatalf("proceso protegido sin ruta: Severity = %s, want INFO", got.Severity)
	}
}

func TestIFEOKnownDebuggerIsInfo(t *testing.T) {
	vs := art("ifeo_debugger", "AeDebug", map[string]string{"image": "x.exe", "debugger": `"C:\Windows\system32\vsjitdebugger.exe" -p %ld`})
	if got := escalate(vs, ruleFor("ifeo_debugger")); got.Severity != SevInfo {
		t.Fatalf("vsjitdebugger: %s", got.Severity)
	}
	evil := art("ifeo_debugger", "notepad.exe", map[string]string{"image": "notepad.exe", "debugger": `C:\Temp\x.exe`})
	if got := escalate(evil, ruleFor("ifeo_debugger")); got.Severity != SevMedium {
		t.Fatalf("depurador desconocido: %s", got.Severity)
	}
}

func TestTimeChangeRules(t *testing.T) {
	legit := art("eventlog.time_changed", "Security", map[string]any{"time": time.Now(), "legit": true, "process": `C:\Windows\System32\svchost.exe`})
	if got := escalate(legit, ruleFor("eventlog.time_changed")); got.Severity != SevInfo {
		t.Fatalf("svchost: %s", got.Severity)
	}
	manual := art("eventlog.time_changed", "Security", map[string]any{"time": time.Now(), "legit": false})
	if got := escalate(manual, ruleFor("eventlog.time_changed")); got.Severity != SevLow {
		t.Fatalf("manual solo: %s, want LOW", got.Severity)
	}
}

// TestTimeChangeNearTimestompIsCritical: mover el reloj y timestompear en
// la misma media hora es la receta para fabricar fechas viejas.
func TestTimeChangeNearTimestompIsCritical(t *testing.T) {
	when := time.Date(2026, 8, 4, 12, 0, 0, 0, time.UTC)
	stomp := art("mft_timestomp", `C:\x\y.exe`, map[string]any{"SI": map[string]any{"Created": when}})
	change := art("eventlog.time_changed", "Security", map[string]any{"time": when.Add(10 * time.Minute), "legit": false})
	findings, v := Evaluate([]collector.Result{
		{Collector: "mft_timestomp", Artifacts: []collector.Artifact{stomp}},
		{Collector: "eventlog", Artifacts: []collector.Artifact{change}},
	})
	var stompSev, changeSev string
	for _, f := range findings {
		switch f.Title {
		case titleFor("mft_timestomp"):
			stompSev = f.Severity
		case titleFor("eventlog.time_changed"):
			changeSev = f.Severity
		}
	}
	if stompSev != SevCritical || changeSev != SevMedium {
		t.Fatalf("stomp=%s change=%s", stompSev, changeSev)
	}
	if v.Level != report.LevelEvidenciaFuerte {
		t.Fatalf("Level = %s", v.Level)
	}
}

func TestTimeChangeFarFromTimestompDoesNothing(t *testing.T) {
	when := time.Date(2026, 8, 4, 12, 0, 0, 0, time.UTC)
	stomp := art("mft_timestomp", `C:\x\y.exe`, map[string]any{"SI": map[string]any{"Created": when}})
	change := art("eventlog.time_changed", "Security", map[string]any{"time": when.Add(-3 * 24 * time.Hour), "legit": false})
	findings, _ := Evaluate([]collector.Result{
		{Collector: "mft_timestomp", Artifacts: []collector.Artifact{stomp}},
		{Collector: "eventlog", Artifacts: []collector.Artifact{change}},
	})
	for _, f := range findings {
		if f.Title == titleFor("mft_timestomp") && f.Severity != SevHigh {
			t.Fatalf("timestomp solo debe seguir en HIGH, got %s", f.Severity)
		}
	}
}

// TestNeutralPhase8TypesAreSummarized: autoruns, procesos y entradas de
// inicio son evidencia de alto volumen; sin firma sospechosa se resumen.
func TestNeutralPhase8TypesAreSummarized(t *testing.T) {
	signed := map[string]any{"path": `C:\Program Files\x\x.exe`, "Signature": map[string]string{"Status": "signed"}}
	results := []collector.Result{{Collector: "processes", Artifacts: []collector.Artifact{
		art("process", `C:\Program Files\x\x.exe`, signed),
		art("process", `C:\Program Files\y\y.exe`, signed),
	}}}
	findings, v := Evaluate(results)
	if len(findings) != 1 || findings[0].ID != "summary-processes" {
		t.Fatalf("findings = %+v", findings)
	}
	if v.Level != report.LevelLimpio {
		t.Fatalf("Level = %s", v.Level)
	}
}
