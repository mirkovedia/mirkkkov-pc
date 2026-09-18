//go:build windows

package lockedfile

import (
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/windows"

	"github.com/mirkovedia/mirkkkov-pc/internal/privilege"
)

// lockExclusive abre path sin compartir nada, como hace el kernel con los
// hives montados. Devuelve el handle para que el test lo cierre.
func lockExclusive(t *testing.T, path string) windows.Handle {
	t.Helper()
	p, _ := windows.UTF16PtrFromString(path)
	h, err := windows.CreateFile(p, windows.GENERIC_READ|windows.GENERIC_WRITE, 0, nil,
		windows.OPEN_EXISTING, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func TestFileReferenceWorksOnExclusivelyLockedFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "locked.bin")
	if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	h := lockExclusive(t, path)
	defer windows.CloseHandle(h)

	if _, err := os.ReadFile(path); !isLocked(err) {
		t.Fatalf("el fixture no quedó bloqueado: %v", err)
	}
	ref, err := fileReference(path)
	if err != nil {
		t.Fatalf("fileReference sobre archivo bloqueado: %v", err)
	}
	if ref&mftEntryMask == 0 {
		t.Fatal("file reference vacío")
	}
}

// TestCopyToReadsLockedFileRaw solo corre elevado: abrir el volumen en crudo
// exige administrador. En CI y en una consola normal se salta, pero deja el
// camino real verificable con `go test` desde una consola elevada.
func TestCopyToReadsLockedFileRaw(t *testing.T) {
	if elevated, _ := privilege.IsElevated(); !elevated {
		t.Skip("requiere consola elevada para abrir el volumen en crudo")
	}
	// Más grande que un clúster para forzar $DATA no residente.
	content := make([]byte, 64*1024+123)
	for i := range content {
		content[i] = byte(i % 251)
	}
	path := filepath.Join(t.TempDir(), "hive.bin")
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatal(err)
	}
	h := lockExclusive(t, path)
	defer windows.CloseHandle(h)
	// Forzar que el contenido esté en disco antes de leer el volumen en crudo.
	if err := windows.FlushFileBuffers(h); err != nil {
		t.Fatal(err)
	}

	dst := filepath.Join(t.TempDir(), "copy.bin")
	if err := CopyTo(path, dst); err != nil {
		t.Fatalf("CopyTo: %v", err)
	}
	got, err := os.ReadFile(dst)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != len(content) {
		t.Fatalf("len = %d, want %d", len(got), len(content))
	}
	for i := range got {
		if got[i] != content[i] {
			t.Fatalf("byte %d difiere", i)
		}
	}
}
