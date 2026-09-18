//go:build windows

package ui

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// TestRevealNeverOpensAFileAsIfItWereAFolder: con la ruta "…\x.cmd\y" el
// Stat de la ruta falla y el del "padre" tiene éxito, pero el padre es un
// archivo. Pasárselo a explorer.exe lo EJECUTA. Alcanza un valor en
// HKCU\…\Run para que esa ruta llegue a un hallazgo con botón de carpeta.
//
// El test usa un .txt a propósito: si la regresión volviera, abriría un bloc
// de notas en vez de ejecutar algo. Y un nombre neutro: con "aimbot-loader"
// el escaneo real que corre después en el CI lo encontraba en el USN journal
// del runner y lo reportaba como hallazgo (la detección funciona).
func TestRevealNeverOpensAFileAsIfItWereAFolder(t *testing.T) {
	file := filepath.Join(t.TempDir(), "archivo-del-revisado.txt")
	if err := os.WriteFile(file, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	err := Reveal(filepath.Join(file, "y"))
	if !errors.Is(err, ErrNotRevealable) {
		t.Fatalf("Reveal con un archivo como padre = %v, want ErrNotRevealable", err)
	}
}

func TestRevealMissingParentIsNotRevealable(t *testing.T) {
	err := Reveal(filepath.Join(t.TempDir(), "no-existe", "x.exe"))
	if !errors.Is(err, ErrNotRevealable) {
		t.Fatalf("err = %v, want ErrNotRevealable", err)
	}
}

func TestOnLocalDrive(t *testing.T) {
	if !onLocalDrive(os.TempDir()) {
		t.Fatalf("%s debería estar en un disco local", os.TempDir())
	}
	// Una letra sin unidad detrás no es un disco local (DRIVE_NO_ROOT_DIR).
	for _, letter := range []string{`B:\x`, `Q:\x`} {
		if _, err := os.Stat(letter[:3]); err == nil {
			continue // existe en esta máquina: no sirve para el caso negativo
		}
		if onLocalDrive(letter) {
			t.Errorf("onLocalDrive(%q) = true para una unidad inexistente", letter)
		}
	}
}
