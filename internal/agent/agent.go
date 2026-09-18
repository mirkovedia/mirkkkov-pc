// internal/agent/agent.go
package agent

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/mirkovedia/mirkkkov-pc/internal/collector"
	"github.com/mirkovedia/mirkkkov-pc/internal/report"
	"github.com/mirkovedia/mirkkkov-pc/internal/transport"
	"github.com/mirkovedia/mirkkkov-pc/internal/verdict"
)

// Options configura una ejecución del agente.
type Options struct {
	Timeout   time.Duration
	ServerURL string
	Version   string
	Machine   report.MachineInfo // estado de la máquina (elevación, VM, OS, uptime)
	// Observer, si tiene callbacks, recibe el avance del escaneo. El modo
	// consola lo deja vacío y se comporta exactamente como antes.
	Observer collector.Observer
	// Diagnostics son notas operativas que van al reporte tal cual.
	Diagnostics []string
}

// runWithCollectors ejecuta el flujo completo con colectores y consentimiento
// inyectados (para testeo). El flag consent simula la aceptación del jugador.
func runWithCollectors(ctx context.Context, opts Options, up transport.Uploader, collectors []collector.Collector, consent bool) (report.Report, error) {
	consentAt := time.Now()
	if !consent {
		return report.Report{}, fmt.Errorf("el jugador no otorgó consentimiento; escaneo abortado")
	}

	ctx, cancel := context.WithTimeout(ctx, opts.Timeout)
	defer cancel()

	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		return report.Report{}, err
	}

	sess, err := up.OpenSession(ctx, transport.OpenRequest{
		AgentVersion:    opts.Version,
		Pubkey:          hex.EncodeToString(pub),
		ConsentAt:       consentAt,
		MachineInfoHash: "", // se completa en la integración real
	})
	if err != nil {
		return report.Report{}, fmt.Errorf("no se pudo abrir sesión: %w", err)
	}

	chain := report.NewChain(sess.Nonce)
	rep := report.Report{
		SessionID:    sess.SessionID,
		Platform:     "windows",
		AgentVersion: opts.Version,
		StartedAt:    time.Now(),
		ConsentAt:    consentAt,
		Machine:      opts.Machine,
		Diagnostics:  opts.Diagnostics,
		Nonce:        sess.Nonce,
		Pubkey:       hex.EncodeToString(pub),
		Status:       report.StatusComplete,
	}

	results := collector.RunObserved(ctx, collectors, opts.Observer)
	rep.Collectors = collectorRuns(results)
	// Un contexto agotado o cancelado deja resultados parciales: el reporte
	// tiene que decirlo, porque un veredicto sobre medio escaneo no vale lo
	// mismo que uno sobre el escaneo entero.
	if ctx.Err() != nil {
		rep.Status = report.StatusAborted
	}

	findings, v := verdict.Evaluate(results)
	rep.Verdict = v
	rep.Activity = verdict.Activity(results, time.Now())
	seq := 0
	for _, f := range findings {
		chainHash, err := chain.Append(f)
		if err != nil {
			continue
		}
		rep.Findings = append(rep.Findings, f)
		_ = up.StreamFinding(ctx, sess.SessionID, seq, f, chainHash)
		seq++
	}

	rep.HashChain = chain.Hashes()
	rep.EndedAt = time.Now()
	root := chain.Root()
	rep.Signature = report.Sign(priv, root)

	// Complete se llama con un contexto propio: si el escaneo se canceló, el
	// reporte parcial igual tiene que llegar a disco (o al servidor). Un
	// escaneo abortado sin reporte es un escaneo que nunca existió.
	completeCtx, cancelComplete := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancelComplete()
	if _, err := up.Complete(completeCtx, sess.SessionID, rep, rep.Signature, root); err != nil {
		return rep, fmt.Errorf("no se pudo completar la sesión: %w", err)
	}
	return rep, nil
}

// collectorRuns traduce los resultados crudos al registro de cobertura que
// va en el reporte.
func collectorRuns(results []collector.Result) []report.CollectorRun {
	runs := make([]report.CollectorRun, 0, len(results))
	for _, r := range results {
		run := report.CollectorRun{
			Name:       r.Collector,
			Artifacts:  len(r.Artifacts),
			DurationMs: r.Duration.Milliseconds(),
		}
		if r.Err != nil {
			run.Error = r.Err.Error()
		}
		runs = append(runs, run)
	}
	return runs
}
