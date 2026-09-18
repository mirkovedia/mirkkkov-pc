package vss

import "testing"

// TestValidVolume: el volumen se interpola en un script de PowerShell, así
// que solo puede tener la forma exacta "C:\".
func TestValidVolume(t *testing.T) {
	for _, ok := range []string{`C:\`, `d:\`} {
		if !validVolume(ok) {
			t.Errorf("validVolume(%q) = false", ok)
		}
	}
	for _, bad := range []string{``, `C:`, `C:\Windows`, `C:\'; Remove-Item x; '`, `\\?\C:\`, `CC:\`} {
		if validVolume(bad) {
			t.Errorf("validVolume(%q) = true: no se puede interpolar", bad)
		}
	}
}
