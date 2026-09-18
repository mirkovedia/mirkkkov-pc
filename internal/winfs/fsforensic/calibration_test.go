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
		"_loader.cpython-313.pyc.1861862178608":                          false,
		"esp.dll":                                                        true,
		"run-hook.cmd":                                                   true,
		"injector.exe":                                                   true,
		// Marcador fuerte: cualquier extensión.
		"cheat_notes.txt": true,
	}
	for name, want := range cases {
		if got := IsSuspiciousName(name); got != want {
			t.Errorf("IsSuspiciousName(%q) = %v, want %v", name, got, want)
		}
	}
}
