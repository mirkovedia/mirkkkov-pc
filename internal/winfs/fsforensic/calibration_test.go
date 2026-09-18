package fsforensic

import "testing"

// TestWeakMarkerRequiresForensicExtension: la ejecución real del 2026-08-05
// trajo 174 MEDIUM por assets web de Teams cuyos nombres contienen "esp" y
// "loader" como token. Un marcador débil solo cuenta sobre algo que puede
// ejecutarse; el fuerte sigue contando sobre cualquier nombre.
func TestWeakMarkerRequiresForensicExtension(t *testing.T) {
	cases := map[string]bool{
		"esp-coachmark-7ae3be452b065019.js.gz":                          false,
		"call-emergency-location-loader-2ae33a93c05bd8a0.js.gz":         false,
		"hook-86d7534c-80bb-4f1e-9489-758d77df4bb8-5-systemMessage.txt": false,
		"_loader.cpython-313.pyc.1861862178608":                         false,
		"esp.dll":                                                       true,
		"run-hook.cmd":                                                  true,
		"injector.exe":                                                  true,
		// Marcador fuerte: cualquier extensión.
		"cheat_notes.txt": true,
	}
	for name, want := range cases {
		if got := IsSuspiciousName(name); got != want {
			t.Errorf("IsSuspiciousName(%q) = %v, want %v", name, got, want)
		}
	}
}

// TestWeakMarkerPositionAndVendorNamespaces sale del primer escaneo real en
// un runner elevado (2026-09-18): dos MEDIUM sobre una máquina limpia
// bastaron para un SOSPECHOSO.
func TestWeakMarkerPositionAndVendorNamespaces(t *testing.T) {
	cases := map[string]bool{
		// Los dos falsos positivos reales.
		"System.Runtime.Loader.dll":        false,
		"rust-analyzer-proc-macro-srv.exe": false,
		// Misma familia.
		"Microsoft.Extensions.Hosting.Loader.dll": false,
		`C:\proyecto\loader\main.exe`:             false, // el directorio no cuenta
		// Lo que sí tiene que seguir detectándose.
		"ff_loader_v2.exe":                             true,
		"loader.exe":                                   true,
		"FreeFire_Injector.exe":                        true,
		"INJECTOR.EXE-1A2B3C4D.pf":                     true,
		`C:\Windows\Prefetch\INJECTOR.EXE-1A2B3C4D.pf`: true,
		"macro_v2.ahk":                                 true,
		"esp.dll":                                      true,
		// Un nombre corto con punto no es un espacio de nombres de proveedor.
		"system.loader.exe": true,
	}
	for name, want := range cases {
		if got := IsSuspiciousName(name); got != want {
			t.Errorf("IsSuspiciousName(%q) = %v, want %v", name, got, want)
		}
	}
}
