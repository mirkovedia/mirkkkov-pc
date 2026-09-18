// internal/verdict/calibration_test.go
//
// Fase 8: los casos salen del reporte real del 2026-08-05, que seguía dando
// EVIDENCIA_FUERTE sobre una máquina limpia. Cada test afirma lo que el
// motor debería haber dicho sobre un artefacto que existió de verdad.
package verdict

import (
	"testing"
	"time"

	"github.com/mirkovedia/mirkkkov-pc/internal/collector"
	"github.com/mirkovedia/mirkkkov-pc/internal/report"
)

// TestDriverUnderSystemRootIsInfo: 56 drivers en DriverStore salían MEDIUM
// porque la ruta cruda usa el alias \SystemRoot\ y la regla comparaba contra
// \windows\ literal.
func TestDriverUnderSystemRootIsInfo(t *testing.T) {
	cases := []string{
		`\SystemRoot\System32\DriverStore\FileRepository\acpipagr.inf_amd64_d1093347a27ff89c\acpipagr.sys`,
		`System32\DriverStore\FileRepository\basicrender.inf_amd64_cf45ae7c2c82746d\BasicRender.sys`,
		`\SystemRoot\System32\cdd.dll`,
		`\??\C:\Windows\System32\drivers\wd\WdFilter.sys`,
	}
	for _, p := range cases {
		a := art("service_driver", p, map[string]any{"Name": "x", "ImagePath": p, "Type": 1, "Start": 3})
		got := escalate(a, ruleFor("service_driver"))
		if got.Severity != SevInfo {
			t.Errorf("%s: Severity = %s, want INFO", p, got.Severity)
		}
	}
}

func TestDriverOutsideWindowsDirStaysMedium(t *testing.T) {
	p := `\??\C:\Users\x\AppData\Local\Temp\dropper.sys`
	a := art("service_driver", p, map[string]any{"Name": "x", "ImagePath": p, "Type": 1, "Start": 3})
	if got := escalate(a, ruleFor("service_driver")); got.Severity != SevMedium {
		t.Fatalf("Severity = %s, want MEDIUM", got.Severity)
	}
}

// TestServiceNoInstallLogIsInfo: los logs rotan. Un driver instalado hace
// meses nunca va a tener su evento 7045 disponible, igual que ya se resolvió
// para task_no_register_log.
func TestServiceNoInstallLogIsInfo(t *testing.T) {
	a := art("eventlog.desync", "acpipagr", map[string]string{"Kind": "service_no_install_log", "Subject": "acpipagr"})
	if got := escalate(a, ruleFor("eventlog.desync")); got.Severity != SevInfo {
		t.Fatalf("Severity = %s, want INFO", got.Severity)
	}
	b := art("eventlog.desync", "x", map[string]string{"Kind": "service_installed_then_removed", "Subject": "x"})
	if got := escalate(b, ruleFor("eventlog.desync")); got.Severity != SevMedium {
		t.Fatalf("installed_then_removed debe seguir en MEDIUM, got %s", got.Severity)
	}
}

// TestHiveOnlyPerUserWindowsTaskIsInfo: el único CRITICAL del reporte fue
// PostponeDeviceSetupToast_<SID>_0, una tarea que Windows crea por usuario en
// la raíz del árbol, fuera de Microsoft\. Windows la registra y la borra
// solo; no distingue nada.
func TestHiveOnlyPerUserWindowsTaskIsInfo(t *testing.T) {
	cases := []string{
		`PostponeDeviceSetupToast_S-1-5-21-1778552188-470687461-3181888978-1001_0`,
		`Optimize Start Menu Cache Files-S-1-5-21-1778552188-470687461-3181888978-1001`,
		`User_Feed_Synchronization-{6BB7D5C9-0E1B-4B6E-9C2C-2B9B4C0A9F11}`,
		`OneDrive Standalone Update Task-S-1-5-21-1283052183-2762480918-2325992584-500`,
		`MicrosoftEdgeUpdateTaskMachineUA{7C1E4A2B-0000-4000-8000-000000000000}`,
	}
	for _, rel := range cases {
		a := art("scheduled_task_desync", rel, map[string]string{"RelPath": rel, "Kind": "hive_only", "TaskCacheID": "{X}"})
		if got := escalate(a, ruleFor("scheduled_task_desync")); got.Severity != SevInfo {
			t.Errorf("%s: Severity = %s, want INFO", rel, got.Severity)
		}
	}
}

func TestHiveOnlyUnknownTaskStaysHigh(t *testing.T) {
	a := art("scheduled_task_desync", `Updater\svc`, map[string]string{"RelPath": `Updater\svc`, "Kind": "hive_only", "TaskCacheID": "{X}"})
	if got := escalate(a, ruleFor("scheduled_task_desync")); got.Severity != SevHigh {
		t.Fatalf("Severity = %s, want HIGH", got.Severity)
	}
}

// TestWeakMarkerOnNonExecutableDoesNotEscalate: 174 MEDIUM eran assets web de
// Teams ("esp-coachmark-…js.gz", "…-loader-….js.gz"). Un marcador débil
// sobre un archivo que no puede ejecutarse no es evidencia de nada.
func TestWeakMarkerOnNonExecutableDoesNotEscalate(t *testing.T) {
	cases := []string{
		`\<sin-resolver>\esp-coachmark-7ae3be452b065019.js.gz`,
		`\<sin-resolver>\call-emergency-location-loader-2ae33a93c05bd8a0.js.gz`,
		`\<sin-resolver>\hook-86d7534c-80bb-4f1e-9489-758d77df4bb8-5-systemMessage.txt`,
		`\<sin-resolver>\_loader.cpython-313.pyc.1861862178608`,
	}
	for _, p := range cases {
		a := art("usn", p, map[string]any{"FileName": p, "Suspicious": true})
		if got := escalate(a, ruleFor("usn")); got.Severity != SevInfo {
			t.Errorf("%s: Severity = %s, want INFO", p, got.Severity)
		}
	}
	// El mismo token sobre una DLL sí sigue contando.
	a := art("usn", `C:\Users\x\Downloads\esp.dll`, nil)
	if got := escalate(a, ruleFor("usn")); got.Severity != SevMedium {
		t.Fatalf("esp.dll: Severity = %s, want MEDIUM", got.Severity)
	}
}

// TestEvaluateAssignsTimestamp: el motor calculaba la fecha del hecho para
// los combos pero nunca la guardaba en el hallazgo, así que el reporte salía
// sin fechas y la interfaz no podía ordenar nada en el tiempo.
func TestEvaluateAssignsTimestamp(t *testing.T) {
	when := time.Date(2026, 8, 4, 11, 58, 39, 0, time.UTC)
	a := art("mft_timestomp", `C:\x\cheat.exe`, map[string]any{"SI": map[string]any{"Created": when}})
	findings, _ := Evaluate([]collector.Result{{Collector: "mft_timestomp", Artifacts: []collector.Artifact{a}}})
	if len(findings) == 0 {
		t.Fatal("sin hallazgos")
	}
	if findings[0].Timestamp == nil || !findings[0].Timestamp.Equal(when) {
		t.Fatalf("Timestamp = %v, want %v", findings[0].Timestamp, when)
	}
}

// TestRealMachineScenarioIsLimpio recompone, con artefactos representativos
// del reporte del 2026-08-05, el escaneo que dio EVIDENCIA_FUERTE. Con la
// calibración de esta fase tiene que dar LIMPIO.
func TestRealMachineScenarioIsLimpio(t *testing.T) {
	drv := func(p string) collector.Artifact {
		return art("service_driver", p, map[string]any{"Name": "d", "ImagePath": p, "Type": 1, "Start": 3})
	}
	usn := func(p string) collector.Artifact {
		return art("usn", p, map[string]any{"FileName": p, "Suspicious": true, "Timestamp": time.Now()})
	}
	desync := func(kind, subject string) collector.Artifact {
		return art("eventlog.desync", subject, map[string]string{"Kind": kind, "Subject": subject})
	}
	task := func(kind, rel string) collector.Artifact {
		return art("scheduled_task_desync", rel, map[string]string{"RelPath": rel, "Kind": kind})
	}
	results := []collector.Result{
		{Collector: "services", Artifacts: []collector.Artifact{
			drv(`\SystemRoot\System32\DriverStore\FileRepository\acpipagr.inf_amd64_d1093347a27ff89c\acpipagr.sys`),
			drv(`\SystemRoot\System32\DriverStore\FileRepository\basicdisplay.inf_amd64_9f34636ebdd89def\BasicDisplay.sys`),
			drv(`\SystemRoot\System32\cdd.dll`),
		}},
		{Collector: "usn", Artifacts: []collector.Artifact{
			usn(`\<sin-resolver>\esp-coachmark-7ae3be452b065019.js.gz`),
			usn(`\<sin-resolver>\calling-cdl-calling-package-loader-46ac9bff3e57545a.js.gz`),
			usn(`\<sin-resolver>\esp-locale-ar-sa-8e52d24eae13d3d2.js.gz`),
		}},
		{Collector: "eventlog", Artifacts: []collector.Artifact{
			desync("service_no_install_log", "acpipagr"),
			desync("service_no_install_log", "BasicDisplay"),
			desync("task_no_register_log", `GoogleSystem\GoogleUpdater\x`),
			art("eventlog.tamper_signal", "TaskScheduler", map[string]string{"Kind": "log_unreadable"}),
			art("eventlog.tamper_signal", "System", map[string]string{"Kind": "dirty_flag"}),
		}},
		{Collector: "scheduled_tasks", Artifacts: []collector.Artifact{
			task("hive_only", `PostponeDeviceSetupToast_S-1-5-21-1778552188-470687461-3181888978-1001_0`),
			task("file_only", `Microsoft\Windows\Input\InputSettingsRestoreDataAvailable`),
			task("file_only", `OneDrive Standalone Update Task-S-1-5-21-1283052183-2762480918-2325992584-500`),
			art("scheduled_task", `Microsoft\Windows\AppID\SmartScreenSpecific`,
				map[string]any{"RelPath": `Microsoft\Windows\AppID\SmartScreenSpecific`, "Hidden": true}),
		}},
		{Collector: "deleted_entries", Artifacts: []collector.Artifact{
			art("deleted_entry", `\<sin-resolver>\reghive.test.exe`, map[string]any{"FileName": "reghive.test.exe"}),
			art("deleted_entry", `\<sin-resolver>\AM_Delta.exe`, map[string]any{"FileName": "AM_Delta.exe"}),
		}},
		{Collector: "prefetch", Artifacts: []collector.Artifact{art("prefetch", `C:\Windows\Prefetch\GO.EXE-1.pf`, nil)}},
	}
	_, v := Evaluate(results)
	if v.Level != report.LevelLimpio {
		t.Fatalf("Level = %s (%s), razones %v; want LIMPIO", v.Level, v.Summary, v.Reasons)
	}
}
