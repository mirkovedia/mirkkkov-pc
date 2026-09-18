package verdict

import (
	"testing"

	"github.com/mirkovedia/mirkkkov-pc/internal/report"
)

// TestSummaryAgreesInNumber: el modo consola y -verify decían "1 señales
// críticas". Es un detalle, pero es lo primero que lee quien revisa.
func TestSummaryAgreesInNumber(t *testing.T) {
	cases := []struct {
		level                     string
		criticals, highs, mediums int
		failed                    []string
		want                      string
	}{
		{report.LevelEvidenciaFuerte, 1, 0, 0, nil, "Evidencia fuerte: 1 señal crítica y 0 de alta severidad."},
		{report.LevelEvidenciaFuerte, 2, 3, 0, nil, "Evidencia fuerte: 2 señales críticas y 3 de alta severidad."},
		{report.LevelSospechoso, 0, 1, 2, nil, "Indicios a revisar: 1 señal de alta severidad y 2 de severidad media."},
		{report.LevelSospechoso, 0, 0, 2, nil, "Indicios a revisar: 0 señales de alta severidad y 2 de severidad media."},
		{report.LevelIncompleto, 0, 0, 0, []string{"usn"}, "Sin hallazgos, pero el escaneo fue parcial: falló 1 colector."},
		{report.LevelIncompleto, 0, 0, 0, []string{"usn", "bam"}, "Sin hallazgos, pero el escaneo fue parcial: fallaron 2 colectores."},
		{report.LevelLimpio, 0, 0, 0, nil, "Sin hallazgos relevantes."},
	}
	for _, c := range cases {
		if got := summaryFor(c.level, c.criticals, c.highs, c.mediums, c.failed); got != c.want {
			t.Errorf("summaryFor(%s) = %q, want %q", c.level, got, c.want)
		}
	}
}
