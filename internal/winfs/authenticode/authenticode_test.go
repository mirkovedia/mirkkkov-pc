package authenticode

import "testing"

func TestVerifyEmptyPathIsUnknown(t *testing.T) {
	r := Verify("   ")
	if r.Status != StatusUnknown {
		t.Fatalf("Status = %s, want unknown", r.Status)
	}
}

func TestVerifyMissingFileIsUnknownNotUnsigned(t *testing.T) {
	// Un archivo que no existe no es "sin firma": es "no sé". Confundirlos
	// convierte un borrado en una acusación.
	r := Verify(`C:\no\existe\nunca\x.sys`)
	if r.Status != StatusUnknown {
		t.Fatalf("Status = %s, want unknown (%s)", r.Status, r.Detail)
	}
}

func TestVerifyCachesByPathCaseInsensitive(t *testing.T) {
	ResetCache()
	cache.Store(`c:\fake\a.exe`, Result{Status: StatusSigned, Signer: "cache"})
	if r := Verify(`C:\FAKE\A.EXE`); r.Signer != "cache" {
		t.Fatalf("la caché debe ser insensible a mayúsculas: %+v", r)
	}
	ResetCache()
}

func TestIsTrusted(t *testing.T) {
	if !(Result{Status: StatusSigned}).IsTrusted() {
		t.Fatal("signed debe ser confiable")
	}
	for _, s := range []Status{StatusUnsigned, StatusInvalid, StatusUnknown} {
		if (Result{Status: s}).IsTrusted() {
			t.Fatalf("%s no debe ser confiable", s)
		}
	}
}

// TestPackagedAppsAreNeverUnsigned: la calibración real de Fase 8 marcó
// WhatsApp.Root.exe y WidgetService.exe como "sin firma". Las apps MSIX se
// firman a nivel de paquete; afirmar que no tienen firma es falso.
func TestPackagedAppsAreNeverUnsigned(t *testing.T) {
	ResetCache()
	for _, p := range []string{
		`C:\Program Files\WindowsApps\5319275A.WhatsAppDesktop_2.2636.100.0_x64__cv1g1gvanyjgm\WhatsApp.Root.exe`,
		`c:\program files\windowsapps\Microsoft.WidgetsPlatformRuntime_1.6.19.0_x64__8wekyb3d8bbwe\WidgetService\WidgetService.exe`,
	} {
		r := Verify(p)
		if r.Status != StatusUnknown || r.Detail == "" {
			t.Errorf("%s: %+v, want unknown con detalle", p, r)
		}
	}
}
