package lockedfile

import (
	"os"
	"path/filepath"
	"testing"
)

func TestStageCopiesReadableFileAndCleansUp(t *testing.T) {
	src := filepath.Join(t.TempDir(), "SYSTEM")
	if err := os.WriteFile(src, []byte("regf"), 0o600); err != nil {
		t.Fatal(err)
	}
	st, err := NewStage()
	if err != nil {
		t.Fatal(err)
	}
	dst, err := st.Copy(src)
	if err != nil {
		t.Fatal(err)
	}
	if got, _ := os.ReadFile(dst); string(got) != "regf" {
		t.Fatalf("copia = %q", got)
	}
	dir := st.Dir()
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Fatal("Close debe borrar el directorio del stage")
	}
}

func TestStageCopyMissingFileLeavesNothing(t *testing.T) {
	st, err := NewStage()
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if _, err := st.Copy(filepath.Join(t.TempDir(), "no-existe")); err == nil {
		t.Fatal("esperaba error")
	}
	entries, _ := os.ReadDir(st.Dir())
	if len(entries) != 0 {
		t.Fatalf("el stage no debe quedar con archivos a medias: %v", entries)
	}
}

// TestNewStageRemovesStaleDirs: una ejecución que murió deja su directorio;
// la siguiente lo borra al arrancar.
func TestNewStageRemovesStaleDirs(t *testing.T) {
	stale, err := os.MkdirTemp("", stagePrefix+"stale-*")
	if err != nil {
		t.Fatal(err)
	}
	st, err := NewStage()
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if _, err := os.Stat(stale); !os.IsNotExist(err) {
		os.RemoveAll(stale)
		t.Fatal("NewStage debe borrar los stages de ejecuciones anteriores")
	}
}
