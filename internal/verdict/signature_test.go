// internal/verdict/signature_test.go
//
// Fase 8: la firma Authenticode reemplaza a la heurística por ruta como
// criterio principal. Los casos vienen del reporte real: xhunter1.sys y
// xspirit.sys (anticheat de otro juego, firmados por Wellbia, en C:\Windows)
// y las tareas ocultas de Google y MSI, con ejecutables firmados.
package verdict

import (
	"testing"

	"github.com/mirkovedia/mirkkkov-pc/internal/collector"
	"github.com/mirkovedia/mirkkkov-pc/internal/report"
)

func driverWithSig(path, status string) collector.Artifact {
	return art("service_driver", path, map[string]any{
		"Name": "d", "ImagePath": path, "Type": 1, "Start": 3,
		"Signature": map[string]string{"Status": status, "Signer": "X"},
	})
}

func TestSignedDriverAnywhereIsInfo(t *testing.T) {
	for _, p := range []string{`\??\C:\Windows\xhunter1.sys`, `\??\C:\Windows\xspirit.sys`, `C:\Users\x\AppData\Local\Temp\drv.sys`} {
		if got := escalate(driverWithSig(p, "signed"), ruleFor("service_driver")); got.Severity != SevInfo {
			t.Errorf("%s firmado: Severity = %s, want INFO", p, got.Severity)
		}
	}
}

func TestUnsignedDriverOutsideNormalPathsIsHigh(t *testing.T) {
	for _, status := range []string{"unsigned", "invalid"} {
		got := escalate(driverWithSig(`\??\C:\Users\x\AppData\Local\Temp\drv.sys`, status), ruleFor("service_driver"))
		if got.Severity != SevHigh {
			t.Errorf("%s en Temp: Severity = %s, want HIGH", status, got.Severity)
		}
	}
}

func TestUnsignedDriverInNormalPathIsMedium(t *testing.T) {
	got := escalate(driverWithSig(`C:\Program Files\Vendor\drv.sys`, "unsigned"), ruleFor("service_driver"))
	if got.Severity != SevMedium {
		t.Fatalf("Severity = %s, want MEDIUM", got.Severity)
	}
}

func TestUnknownSignatureFallsBackToPathHeuristic(t *testing.T) {
	// Archivo borrado o API caída: nunca es evidencia por sí mismo.
	if got := escalate(driverWithSig(`\SystemRoot\System32\DriverStore\x\y.sys`, "unknown"), ruleFor("service_driver")); got.Severity != SevInfo {
		t.Fatalf("unknown en ruta normal: Severity = %s, want INFO", got.Severity)
	}
	if got := escalate(driverWithSig(`C:\Temp\y.sys`, "unknown"), ruleFor("service_driver")); got.Severity != SevMedium {
		t.Fatalf("unknown fuera: Severity = %s, want MEDIUM", got.Severity)
	}
}

func TestUntrustedDriverGetsSpecificTitle(t *testing.T) {
	if got := titleOf(driverWithSig(`C:\Temp\y.sys`, "unsigned")); got != "Driver de kernel sin firma válida" {
		t.Fatalf("title = %q", got)
	}
	if got := titleOf(driverWithSig(`C:\Temp\y.sys`, "signed")); got != titleFor("service_driver") {
		t.Fatalf("un driver firmado conserva el título del tipo, got %q", got)
	}
}

func hiddenTask(rel, status string) collector.Artifact {
	return art("scheduled_task", rel, map[string]any{
		"RelPath": rel, "Command": `"C:\Program Files\x\y.exe"`, "Hidden": true,
		"Signature": map[string]string{"Status": status},
	})
}

func TestHiddenTaskWithSignedCommandIsInfo(t *testing.T) {
	for _, rel := range []string{`GoogleSystem\GoogleUpdater\GoogleUpdaterTaskSystem152.0.7933.0{F4EE165D}`, `OmApSvcBroker`} {
		if got := escalate(hiddenTask(rel, "signed"), ruleFor("scheduled_task")); got.Severity != SevInfo {
			t.Errorf("%s firmada: Severity = %s, want INFO", rel, got.Severity)
		}
	}
}

func TestHiddenTaskWithUnsignedCommandStaysMedium(t *testing.T) {
	got := escalate(hiddenTask(`Updater\svc`, "unsigned"), ruleFor("scheduled_task"))
	if got.Severity != SevMedium {
		t.Fatalf("Severity = %s, want MEDIUM", got.Severity)
	}
	if titleOf(hiddenTask(`Updater\svc`, "unsigned")) != "Tarea programada oculta con ejecutable sin firma" {
		t.Fatal("título específico esperado")
	}
}

// TestRealMachineWithSignaturesIsLimpio completa el escenario real con lo
// que la calibración por ruta no podía resolver: los dos drivers de Wellbia
// en C:\Windows y las tareas ocultas de Google y MSI.
func TestRealMachineWithSignaturesIsLimpio(t *testing.T) {
	results := []collector.Result{
		{Collector: "services", Artifacts: []collector.Artifact{
			driverWithSig(`\??\C:\Windows\xhunter1.sys`, "signed"),
			driverWithSig(`\??\C:\Windows\xspirit.sys`, "signed"),
			driverWithSig(`\SystemRoot\System32\DriverStore\FileRepository\acpipagr.inf_amd64_d1093347a27ff89c\acpipagr.sys`, "signed"),
		}},
		{Collector: "scheduled_tasks", Artifacts: []collector.Artifact{
			hiddenTask(`GoogleSystem\GoogleUpdater\GoogleUpdaterTaskSystem152.0.7933.0{F4EE165D-227F-42C1-AB56-1EACE14E8241}`, "signed"),
			hiddenTask(`OmApSvcBroker`, "signed"),
		}},
	}
	_, v := Evaluate(results)
	if v.Level != report.LevelLimpio {
		t.Fatalf("Level = %s (%s) %v; want LIMPIO", v.Level, v.Summary, v.Reasons)
	}
}
