package agent

import (
	"context"
	"testing"
	"time"

	"github.com/mirkovedia/mirkkkov-pc/internal/report"
)

// TestReportIsSelfVerifiable: el reporte local tiene que poder verificarse
// sin servidor. Antes llevaba la firma pero no la clave pública ni el nonce,
// así que la firma era un número que nadie podía comprobar.
func TestReportIsSelfVerifiable(t *testing.T) {
	up := &fakeUploader{}
	opts := Options{Timeout: time.Minute, Version: "test"}
	rep, err := runWithCollectors(context.Background(), opts, up, testCollectors(), true)
	if err != nil {
		t.Fatalf("runWithCollectors: %v", err)
	}
	if rep.Pubkey == "" || rep.Nonce != "n1" {
		t.Fatalf("Pubkey=%q Nonce=%q: el reporte debe llevar ambos", rep.Pubkey, rep.Nonce)
	}
	if err := report.VerifyReport(rep); err != nil {
		t.Fatalf("el reporte recién generado debe verificar: %v", err)
	}
}

func TestReportRecordsCollectorRuns(t *testing.T) {
	up := &fakeUploader{}
	rep, err := runWithCollectors(context.Background(), Options{Timeout: time.Minute}, up, testCollectors(), true)
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Collectors) != 1 || rep.Collectors[0].Name != "mem" || rep.Collectors[0].Artifacts != 1 {
		t.Fatalf("Collectors = %+v", rep.Collectors)
	}
}

// TestReportStatusIsAbortedWhenContextExpires: un escaneo cortado por timeout
// o por cierre de la ventana deja resultados parciales y el reporte lo tiene
// que decir. Antes salía COMPLETE igual.
func TestReportStatusIsAbortedWhenContextExpires(t *testing.T) {
	up := &fakeUploader{}
	// Un padre ya cancelado reproduce el cierre de la ventana a mitad del
	// escaneo (y evita depender de la resolución del reloj de Windows, que
	// hace flaky cualquier timeout de nanosegundos).
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	rep, err := runWithCollectors(ctx, Options{Timeout: time.Minute}, up, testCollectors(), true)
	if err != nil {
		t.Fatalf("un escaneo abortado igual tiene que producir reporte: %v", err)
	}
	if rep.Status != report.StatusAborted {
		t.Fatalf("Status = %q, want ABORTED", rep.Status)
	}
	if !up.completed {
		t.Fatal("el reporte parcial tiene que llegar a Complete aunque el contexto haya muerto")
	}
}
