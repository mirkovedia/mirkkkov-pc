// internal/verdict/activity.go
package verdict

import (
	"encoding/json"
	"time"

	"github.com/mirkovedia/mirkkkov-pc/internal/collector"
	"github.com/mirkovedia/mirkkkov-pc/internal/report"
)

// Ventana y resolución del registro de actividad.
const (
	ActivityDays   = 30
	activityBucket = time.Hour
	activityLen    = ActivityDays * 24
)

// Canales del registro de actividad. Son las tres preguntas que se hace quien
// revisa: qué corrió, qué pasó con los archivos y cuándo estuvo prendida y en
// uso la máquina.
const (
	ChannelExecution = "execution"
	ChannelFiles     = "files"
	ChannelSession   = "session"
)

// channelOf asigna un tipo de artefacto a su canal. Los tipos sin fecha de
// hecho (servicios, tareas, configuración) no van a ninguno.
func channelOf(artifactType string) string {
	switch artifactType {
	case "prefetch", "bam", "process":
		return ChannelExecution
	case "usn", "deleted_entry", "mft_timestomp":
		return ChannelFiles
	case "eventlog.session_timeline", "eventlog.log_cleared", "eventlog.time_changed":
		return ChannelSession
	}
	return ""
}

// Activity arma el histograma por hora de los últimos ActivityDays días a
// partir de TODOS los artefactos con fecha, incluida la evidencia neutra que
// el reporte solo resume. Son conteos por hora: no agrega ningún dato que no
// estuviera ya en el consentimiento, y es lo que permite dibujar la actividad
// de la máquina en el tiempo en vez de describirla con números sueltos.
//
// Siempre devuelve los tres canales, aunque estén vacíos, para que la
// interfaz dibuje los tres carriles.
func Activity(results []collector.Result, now time.Time) *report.Activity {
	from := now.UTC().Truncate(activityBucket).Add(-time.Duration(activityLen-1) * activityBucket)
	act := &report.Activity{
		From:          from,
		BucketMinutes: int(activityBucket / time.Minute),
		Channels: map[string][]int{
			ChannelExecution: make([]int, activityLen),
			ChannelFiles:     make([]int, activityLen),
			ChannelSession:   make([]int, activityLen),
		},
	}
	for _, res := range results {
		if res.Err != nil {
			continue
		}
		for _, a := range res.Artifacts {
			ch := channelOf(a.Type)
			if ch == "" {
				continue
			}
			for _, t := range timesOf(a) {
				idx := int(t.Sub(from) / activityBucket)
				if t.Before(from) || idx < 0 || idx >= activityLen {
					continue // fuera de la ventana, o un reloj adelantado
				}
				act.Channels[ch][idx]++
			}
		}
	}
	return act
}

// timesOf devuelve todas las fechas de hecho de un artefacto. Casi siempre es
// una (la de timeOf); Prefetch guarda hasta ocho ejecuciones por programa y
// todas cuentan para la actividad.
func timesOf(a collector.Artifact) []time.Time {
	if a.Type == "prefetch" {
		var p struct {
			LastRunTimes []time.Time
		}
		if err := json.Unmarshal(a.Data, &p); err != nil {
			return nil
		}
		out := make([]time.Time, 0, len(p.LastRunTimes))
		for _, t := range p.LastRunTimes {
			if !t.IsZero() {
				out = append(out, t)
			}
		}
		return out
	}
	if t, ok := timeOf(a); ok {
		return []time.Time{t}
	}
	return nil
}
