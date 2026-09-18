package collector

import (
	"context"
	"fmt"
	"sort"
	"time"
)

// Result es el resultado de ejecutar un Collector.
type Result struct {
	Collector string
	Artifacts []Artifact
	Err       error
	// Duration es cuánto tardó el colector. Va al reporte: cuando a alguien le
	// falla o se le cuelga una fuente, es el único dato para diagnosticarlo.
	Duration time.Duration
}

// Observer recibe el avance del escaneo. Cualquiera de sus campos puede ser
// nil: existe para que una interfaz muestre progreso en vivo sin que los
// colectores sepan que hay una interfaz.
type Observer struct {
	// OnStart se invoca antes de correr cada colector. index es 1-based.
	OnStart func(index, total int, name string)
	// OnFinish se invoca al terminar cada colector, con su resultado (que
	// puede traer Err: un colector caído también se reporta).
	OnFinish func(index, total int, res Result)
	// OnProgress recibe el avance INTERNO de los colectores que lo informan.
	// Sin esto la barra queda congelada durante los colectores largos, que
	// son justamente los que más tardan.
	OnProgress func(index, total int, name string, done, unitTotal int64)
}

// Run ejecuta los colectores ordenados por prioridad ascendente. Un panic
// dentro de un colector se recupera y se traduce a Result.Err: un colector
// que falla nunca tumba el escaneo.
func Run(ctx context.Context, collectors []Collector) []Result {
	return RunObserved(ctx, collectors, Observer{})
}

// RunObserved es Run con notificaciones de avance.
//
// Si el contexto ya está cancelado al llegar a un colector, ese colector no
// se ejecuta y queda registrado con ctx.Err(): correr diez colectores más
// sobre un contexto muerto solo produce diez errores idénticos y demora la
// salida cuando el usuario ya cerró la ventana.
func RunObserved(ctx context.Context, collectors []Collector, obs Observer) []Result {
	ordered := make([]Collector, len(collectors))
	copy(ordered, collectors)
	sort.SliceStable(ordered, func(i, j int) bool {
		return ordered[i].Priority() < ordered[j].Priority()
	})

	total := len(ordered)
	results := make([]Result, 0, total)
	for i, c := range ordered {
		index := i + 1
		if obs.OnStart != nil {
			obs.OnStart(index, total, c.Name())
		}
		// Los colectores que saben informar avance quedan conectados antes de
		// arrancar; los demás simplemente no implementan la interfaz.
		if obs.OnProgress != nil {
			if rep, ok := c.(Reporter); ok {
				name := c.Name()
				rep.SetProgress(func(done, unitTotal int64) {
					obs.OnProgress(index, total, name, done, unitTotal)
				})
			}
		}
		var res Result
		if err := ctx.Err(); err != nil {
			res = Result{Collector: c.Name(), Err: err}
		} else {
			res = runOne(ctx, c)
		}
		if obs.OnFinish != nil {
			obs.OnFinish(index, total, res)
		}
		results = append(results, res)
	}
	return results
}

func runOne(ctx context.Context, c Collector) (res Result) {
	res.Collector = c.Name()
	started := time.Now()
	defer func() {
		res.Duration = time.Since(started)
		if r := recover(); r != nil {
			res.Err = fmt.Errorf("panic en colector %s: %v", c.Name(), r)
		}
	}()
	res.Artifacts, res.Err = c.Collect(ctx)
	return res
}
