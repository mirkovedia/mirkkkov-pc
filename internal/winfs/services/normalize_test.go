package services

import "testing"

// TestNormalizeImagePathIsExported: el motor de severidad necesita la misma
// normalización que el filtro de drivers; antes cada uno tenía la suya y
// discrepaban (\SystemRoot\ contra \windows\), que es la causa de 56 falsos
// positivos del reporte real del 2026-08-05.
func TestNormalizeImagePathIsExported(t *testing.T) {
	cases := map[string]string{
		`\SystemRoot\System32\DriverStore\x\y.sys`: `c:\windows\system32\driverstore\x\y.sys`,
		`\??\C:\Windows\xhunter1.sys`:              `c:\windows\xhunter1.sys`,
		`system32\drivers\netbt.sys`:               `c:\windows\system32\drivers\netbt.sys`,
		`C:\Program Files\App\drv.sys`:             `c:\program files\app\drv.sys`,
	}
	for in, want := range cases {
		if got := NormalizeImagePath(in); got != want {
			t.Errorf("NormalizeImagePath(%q) = %q, want %q", in, got, want)
		}
	}
}
