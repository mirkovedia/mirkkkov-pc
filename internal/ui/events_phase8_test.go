package ui

import (
	"encoding/json"
	"testing"
)

// TestScanDoneCarriesReportPath: la pantalla de resultados mostraba la ruta
// del reporte leyendo un campo que el JSON nunca tuvo. Ahora viaja en el
// evento, separado del reporte firmado.
func TestScanDoneCarriesReportPath(t *testing.T) {
	e := Event{Kind: KindScanDone, ReportPath: `C:\tools\reporte.json`}
	raw, err := e.JSON()
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]any
	if err := json.Unmarshal([]byte(raw), &got); err != nil {
		t.Fatal(err)
	}
	if got["reportPath"] != `C:\tools\reporte.json` {
		t.Fatalf("reportPath = %v", got["reportPath"])
	}
}
