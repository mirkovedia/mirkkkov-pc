package ui

import "testing"

func TestRevealablePathAcceptsRealPaths(t *testing.T) {
	ok := []string{
		`C:\Users\mirko\Downloads\algo.exe`,
		`C:/Users/mirko/algo.exe`,
		`D:\Temp\x.sys`,
	}
	for _, p := range ok {
		if !RevealablePath(p) {
			t.Errorf("RevealablePath(%q) = false, debería aceptarse", p)
		}
	}
}

// TestRevealablePathRejectsNonFiles cubre los artefactos que no son archivos:
// ofrecerles un botón de carpeta sería prometer algo imposible.
func TestRevealablePathRejectsNonFiles(t *testing.T) {
	no := []string{
		"",
		`Microsoft\Windows\Application Experience\AitAgent`, // tarea programada
		"EvilDrv",                      // nombre de servicio
		`\<sin-resolver>\run-hook.cmd`, // el MFT no resolvió el padre
		"prefetch",                     // nombre de colector
		"C:\nmalicioso",                // salto de línea
		`1:\x.exe`,                     // la "unidad" tiene que ser una letra
	}
	for _, p := range no {
		if RevealablePath(p) {
			t.Errorf("RevealablePath(%q) = true, no es una ubicación del disco", p)
		}
	}
}

// TestRevealablePathRejectsNetworkAndDevicePaths: la ruta la controla quien es
// revisado. Un Stat sobre un UNC desde el proceso elevado autentica por SMB
// contra un host elegido por esa persona y congela la ventana; las rutas de
// dispositivo abren pipes y volúmenes. Antes de la Fase 9 este test
// consagraba el UNC como aceptable.
func TestRevealablePathRejectsNetworkAndDevicePaths(t *testing.T) {
	no := []string{
		`\\servidor\compartido\x.dll`,
		`\\203.0.113.7\s\aimbot.exe`,
		`\\?\C:\Windows\x.exe`,
		`\\.\pipe\algo`,
		`\\?\UNC\host\share\x.exe`,
		`//host/share/x.exe`,
	}
	for _, p := range no {
		if RevealablePath(p) {
			t.Errorf("RevealablePath(%q) = true: no se puede tocar la red ni un dispositivo", p)
		}
	}
}

func TestRevealRejectsNonRevealable(t *testing.T) {
	if err := Reveal(`Microsoft\Windows\Foo`); err == nil {
		t.Fatal("esperaba error para una ruta que no es del disco")
	}
	if err := Reveal(`\\203.0.113.7\s\aimbot.exe`); err == nil {
		t.Fatal("esperaba error para una ruta UNC")
	}
}
