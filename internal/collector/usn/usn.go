//go:build windows

// internal/collector/usn/usn.go
package usn

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/mirkovedia/mirkkkov-pc/internal/collector"
	winusn "github.com/mirkovedia/mirkkkov-pc/internal/winfs/usn"
)

// Collector lee eventos relevantes del USN Change Journal del volumen y
// deja constancia del estado del journal mismo: si no existe o si fue
// recreado hace poco, eso es evidencia por sí solo.
type Collector struct {
	Volume string
	// InstallDate es la fecha de instalación de Windows; cero si no se
	// conoce. Sin ella no se afirma que el journal fue recreado.
	InstallDate time.Time
}

// New crea el colector apuntando al volumen C: por defecto.
func New() *Collector {
	return &Collector{Volume: `\\.\C:`}
}

func (c *Collector) Name() string  { return "usn" }
func (c *Collector) Priority() int { return collector.PriorityDisk }

// JournalState es lo que se reporta cuando el journal falta o es nuevo.
type JournalState struct {
	Volume      string    `json:"volume"`
	JournalID   uint64    `json:"journalId,omitempty"`
	Created     time.Time `json:"created,omitempty"`
	InstallDate time.Time `json:"installDate,omitempty"`
}

func (c *Collector) Collect(ctx context.Context) ([]collector.Artifact, error) {
	now := time.Now()
	artifacts := make([]collector.Artifact, 0)

	info, err := winusn.QueryJournal(c.Volume)
	if errors.Is(err, winusn.ErrJournalNotActive) {
		// Sin journal no hay nada que leer, pero la ausencia misma es el
		// hallazgo: en un Windows normal el journal de C: existe siempre.
		b, _ := json.Marshal(JournalState{Volume: c.Volume})
		return append(artifacts, collector.Artifact{Type: "usn.journal_disabled", Source: c.Volume, Data: b, Collected: now}), nil
	}
	if err != nil {
		return nil, err
	}
	if winusn.Recreated(info.Created, c.InstallDate, now) {
		b, _ := json.Marshal(JournalState{Volume: c.Volume, JournalID: info.ID, Created: info.Created, InstallDate: c.InstallDate})
		artifacts = append(artifacts, collector.Artifact{Type: "usn.journal_recreated", Source: c.Volume, Data: b, Collected: now})
	}

	entries, err := winusn.ReadJournal(ctx, c.Volume)
	if err != nil {
		return artifacts, err
	}
	for _, e := range entries {
		b, _ := json.Marshal(e)
		artifacts = append(artifacts, collector.Artifact{
			Type:      "usn",
			Source:    e.FullPath,
			Data:      b,
			Collected: now,
		})
	}
	return artifacts, nil
}
