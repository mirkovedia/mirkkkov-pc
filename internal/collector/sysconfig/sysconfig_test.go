package sysconfig

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/mirkovedia/mirkkkov-pc/internal/collector"
	"github.com/mirkovedia/mirkkkov-pc/internal/winfs/reghive/reghivetest"
)

func u32(v uint32) []byte {
	return []byte{byte(v), byte(v >> 8), byte(v >> 16), byte(v >> 24)}
}

// buildSystemHive arma ControlSet001 con el valor de EnablePrefetcher y el
// Start del servicio EventLog dados.
func buildSystemHive(t *testing.T, prefetcher, eventlogStart uint32) string {
	t.Helper()
	b := reghivetest.NewBuilder()
	vPf := b.AddValue("EnablePrefetcher", u32(prefetcher), 4)
	pp := b.AddKey("PrefetchParameters", nil, []uint32{vPf})
	mm := b.AddKey("Memory Management", []uint32{pp}, nil)
	sm := b.AddKey("Session Manager", []uint32{mm}, nil)
	control := b.AddKey("Control", []uint32{sm}, nil)
	vStart := b.AddValue("Start", u32(eventlogStart), 4)
	el := b.AddKey("EventLog", nil, []uint32{vStart})
	services := b.AddKey("Services", []uint32{el}, nil)
	cs := b.AddKey("ControlSet001", []uint32{control, services}, nil)
	root := b.AddKey("ROOT", []uint32{cs}, nil)
	path := filepath.Join(t.TempDir(), "SYSTEM")
	if err := os.WriteFile(path, b.Build(root), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func types(arts []collector.Artifact) map[string]int {
	out := map[string]int{}
	for _, a := range arts {
		out[a.Type]++
	}
	return out
}

func TestCollectorMetadata(t *testing.T) {
	c := New("x", time.Time{})
	if c.Name() != "sysconfig" || c.PrefetchDir == "" {
		t.Fatalf("New = %+v", c)
	}
	var _ collector.Collector = c
}

func TestHealthyConfigProducesNothing(t *testing.T) {
	dir := t.TempDir()
	for i := 0; i < 20; i++ {
		os.WriteFile(filepath.Join(dir, "APP.EXE-"+string(rune('A'+i))+".pf"), []byte("x"), 0o644)
	}
	c := &Collector{SystemHive: buildSystemHive(t, 3, 2), PrefetchDir: dir, InstallDate: time.Now().Add(-365 * 24 * time.Hour)}
	arts, err := c.Collect(context.Background())
	if err != nil || len(arts) != 0 {
		t.Fatalf("arts=%v err=%v", types(arts), err)
	}
}

func TestPrefetchDisabledAndEventLogDisabled(t *testing.T) {
	c := &Collector{SystemHive: buildSystemHive(t, 0, 4), PrefetchDir: t.TempDir()}
	arts, err := c.Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	got := types(arts)
	if got["config.prefetch_disabled"] != 1 || got["config.eventlog_disabled"] != 1 {
		t.Fatalf("types = %v", got)
	}
	if got["config.prefetch_empty"] != 0 {
		t.Fatal("con el prefetcher apagado, la carpeta vacía es consecuencia, no señal aparte")
	}
}

func TestEmptyPrefetchOnOldInstallIsReported(t *testing.T) {
	c := &Collector{SystemHive: buildSystemHive(t, 3, 2), PrefetchDir: t.TempDir(), InstallDate: time.Now().Add(-90 * 24 * time.Hour)}
	arts, _ := c.Collect(context.Background())
	if types(arts)["config.prefetch_empty"] != 1 {
		t.Fatalf("types = %v", types(arts))
	}
}

func TestEmptyPrefetchOnFreshInstallIsNormal(t *testing.T) {
	c := &Collector{SystemHive: buildSystemHive(t, 3, 2), PrefetchDir: t.TempDir(), InstallDate: time.Now().Add(-2 * 24 * time.Hour)}
	arts, _ := c.Collect(context.Background())
	if len(arts) != 0 {
		t.Fatalf("types = %v", types(arts))
	}
}

func TestEmptyPrefetchWithoutInstallDateIsNotClaimed(t *testing.T) {
	c := &Collector{SystemHive: buildSystemHive(t, 3, 2), PrefetchDir: t.TempDir()}
	arts, _ := c.Collect(context.Background())
	if len(arts) != 0 {
		t.Fatalf("sin fecha de instalación no se afirma nada: %v", types(arts))
	}
}

func TestUnreadablePrefetchDirIsNotEmpty(t *testing.T) {
	c := &Collector{SystemHive: buildSystemHive(t, 3, 2), PrefetchDir: filepath.Join(t.TempDir(), "no-existe"), InstallDate: time.Now().Add(-90 * 24 * time.Hour)}
	arts, _ := c.Collect(context.Background())
	if len(arts) != 0 {
		t.Fatalf("no poder leer la carpeta no es lo mismo que estar vacía: %v", types(arts))
	}
}
