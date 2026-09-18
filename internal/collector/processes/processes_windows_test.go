//go:build windows

package processes

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/mirkovedia/mirkkkov-pc/internal/collector"
	"github.com/mirkovedia/mirkkkov-pc/internal/winfs/authenticode"
)

func TestCollectorMetadata(t *testing.T) {
	c := New()
	if c.Name() != "processes" || c.Priority() != collector.PriorityVolatile {
		t.Fatalf("metadata = %s/%d", c.Name(), c.Priority())
	}
	var _ collector.Collector = c
}

// TestCollectSeesItself: el proceso de test aparece con su ruta real, con
// hora de inicio y con firma "unsigned" (go test no firma nada). No hace
// falta elevación: enumerar procesos es de cualquier usuario.
func TestCollectSeesItself(t *testing.T) {
	authenticode.ResetCache()
	arts, err := New().Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	exe, _ := os.Executable()
	me := uint32(os.Getpid())
	for _, a := range arts {
		var p Process
		if err := json.Unmarshal(a.Data, &p); err != nil {
			t.Fatal(err)
		}
		if p.PID != me {
			continue
		}
		if !strings.EqualFold(p.Path, exe) {
			t.Fatalf("Path = %q, want %q", p.Path, exe)
		}
		if p.Time.IsZero() {
			t.Fatal("sin hora de inicio")
		}
		if p.Signature.Status != authenticode.StatusUnsigned {
			t.Fatalf("Signature = %+v, want unsigned", p.Signature)
		}
		if a.Source != p.Path {
			t.Fatalf("Source = %q", a.Source)
		}
		return
	}
	t.Fatalf("el proceso de test (pid %d) no aparece entre %d procesos", me, len(arts))
}

func TestCollectUsesInjectedVerifier(t *testing.T) {
	calls := 0
	c := &Collector{Verify: func(string) authenticode.Result {
		calls++
		return authenticode.Result{Status: authenticode.StatusSigned}
	}}
	if _, err := c.Collect(context.Background()); err != nil {
		t.Fatal(err)
	}
	if calls == 0 {
		t.Fatal("el verificador inyectado no se usó")
	}
}
