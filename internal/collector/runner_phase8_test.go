package collector

import (
	"context"
	"errors"
	"testing"
	"time"
)

type slowCollector struct{ stubCollector }

func (s slowCollector) Collect(ctx context.Context) ([]Artifact, error) {
	time.Sleep(2 * time.Millisecond)
	return s.stubCollector.Collect(ctx)
}

func TestRunRecordsDuration(t *testing.T) {
	res := Run(context.Background(), []Collector{slowCollector{stubCollector{name: "lento"}}})
	if res[0].Duration <= 0 {
		t.Fatalf("Duration = %v, esperaba > 0", res[0].Duration)
	}
}

func TestRunRecordsDurationEvenOnPanic(t *testing.T) {
	res := Run(context.Background(), []Collector{stubCollector{name: "boom", panics: true}})
	if res[0].Err == nil {
		t.Fatal("un panic debe traducirse a Err")
	}
	if res[0].Duration < 0 {
		t.Fatalf("Duration = %v", res[0].Duration)
	}
}

// TestRunSkipsCollectorsOnceContextIsDone: cuando el usuario cierra la
// ventana no tiene sentido arrancar los colectores que faltan; cada uno
// devolvería el mismo error y demoraría la salida.
func TestRunSkipsCollectorsOnceContextIsDone(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	res := Run(ctx, []Collector{stubCollector{name: "a"}, stubCollector{name: "b"}})
	if len(res) != 2 {
		t.Fatalf("se esperan 2 resultados (uno por colector, aunque no corran), got %d", len(res))
	}
	for _, r := range res {
		if !errors.Is(r.Err, context.Canceled) {
			t.Errorf("%s: Err = %v, esperaba context.Canceled", r.Collector, r.Err)
		}
	}
}
