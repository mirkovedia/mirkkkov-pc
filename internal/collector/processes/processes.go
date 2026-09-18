// Package processes recolecta los procesos en ejecución en el momento del
// escaneo, con la ruta de su imagen, cuándo arrancaron y si esa imagen tiene
// firma válida. Es el único colector volátil: lo que corre ahora es la
// evidencia más directa de un cheat activo, y desaparece al cerrar la ventana.
//
// Solo metadatos: nombre, ruta, PID, padre, hora de inicio y firma. No se
// lee memoria ni se enumeran módulos.
package processes

import (
	"context"
	"encoding/json"
	"strings"
	"sync"
	"time"

	"github.com/mirkovedia/mirkkkov-pc/internal/collector"
	"github.com/mirkovedia/mirkkkov-pc/internal/winfs/authenticode"
)

// Collector enumera los procesos vivos.
type Collector struct {
	Verify authenticode.Verifier
}

// New crea el colector con el verificador de firmas real.
func New() *Collector { return &Collector{Verify: authenticode.Verify} }

func (c *Collector) Name() string  { return "processes" }
func (c *Collector) Priority() int { return collector.PriorityVolatile }

// Process es un proceso vivo.
type Process struct {
	PID  uint32 `json:"pid"`
	PPID uint32 `json:"ppid"`
	Name string `json:"name"`
	// Path es la ruta de la imagen; vacía si el proceso está protegido y no
	// se pudo consultar.
	Path      string              `json:"path,omitempty"`
	Time      time.Time           `json:"time,omitempty"`
	Signature authenticode.Result `json:"Signature"`
}

// verifyWorkers acota cuántas firmas se comprueban a la vez. WinVerifyTrust
// es seguro entre hilos y cada verificación de catálogo cuesta decenas de
// milisegundos: en serie, doscientos procesos son más de diez segundos.
const verifyWorkers = 8

func (c *Collector) Collect(ctx context.Context) ([]collector.Artifact, error) {
	procs, err := snapshot()
	if err != nil {
		return nil, err
	}
	c.verifyAll(ctx, procs)

	now := time.Now()
	arts := make([]collector.Artifact, 0, len(procs))
	for _, p := range procs {
		source := p.Path
		if source == "" {
			source = p.Name
		}
		b, _ := json.Marshal(p)
		arts = append(arts, collector.Artifact{Type: "process", Source: source, Data: b, Collected: now})
	}
	return arts, ctx.Err()
}

// systemImageDir es donde viven los procesos propios de Windows. No se
// verifican: son la mayoría de la lista, todos vienen firmados por catálogo
// y cada verificación de catálogo cuesta decenas de milisegundos. Un binario
// ajeno ahí dentro necesitó privilegios para llegar, y ese camino lo cubren
// los colectores de servicios y persistencia.
const systemImageDir = `c:\windows\`

// verifyAll completa la firma de cada proceso, en paralelo y respetando el
// contexto: si se cancela, lo que falta queda como unknown.
func (c *Collector) verifyAll(ctx context.Context, procs []Process) {
	for i := range procs {
		procs[i].Signature = authenticode.Result{Status: authenticode.StatusUnknown}
		if strings.HasPrefix(strings.ToLower(procs[i].Path), systemImageDir) {
			procs[i].Signature.Detail = "imagen del sistema: no se verifica"
		}
	}
	if c.Verify == nil {
		return
	}
	var wg sync.WaitGroup
	sem := make(chan struct{}, verifyWorkers)
	for i := range procs {
		if procs[i].Path == "" || procs[i].Signature.Detail != "" || ctx.Err() != nil {
			continue
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(p *Process) {
			defer wg.Done()
			defer func() { <-sem }()
			p.Signature = c.Verify(p.Path)
		}(&procs[i])
	}
	wg.Wait()
}
