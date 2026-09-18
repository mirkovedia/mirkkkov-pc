// internal/verdict/preview.go
package verdict

import (
	"time"

	"github.com/mirkovedia/mirkkkov-pc/internal/collector"
)

// PreviewResult es la clasificación preliminar de un artefacto suelto.
type PreviewResult struct {
	Category string
	Severity string
	Title    string
	// Notable indica si vale la pena mostrarlo en la vista en vivo. La
	// evidencia INFO es el ruido normal de una computadora en uso: mostrarla
	// mientras escanea taparía las señales que importan.
	Notable bool
	// At es la fecha del hecho, si el artefacto la tiene.
	At *time.Time
}

// Preview clasifica un artefacto para mostrarlo mientras el escaneo corre.
//
// Aplica la regla base y el escalado por contenido, que son determinísticos
// por artefacto. NO aplica los combos ni la deduplicación, porque ambos
// necesitan el escaneo terminado: un combo mira señales de otros colectores y
// la deduplicación cuenta repeticiones.
//
// Por eso la severidad que devuelve es PRELIMINAR y puede subir en el
// resultado final. La pantalla de resultados, que usa Evaluate, es la
// autoritativa.
func Preview(a collector.Artifact) PreviewResult {
	r := escalate(a, ruleFor(a.Type))
	var at *time.Time
	if t, ok := timeOf(a); ok {
		at = &t
	}
	return PreviewResult{
		At:       at,
		Category: r.Category,
		Severity: r.Severity,
		Title:    titleOf(a),
		Notable:  severityRank(r.Severity) > severityRank(SevInfo),
	}
}
