// internal/collector/services/services.go
package services

import (
	"context"
	"encoding/json"
	"os"
	"time"

	"github.com/mirkovedia/mirkkkov-pc/internal/collector"
	"github.com/mirkovedia/mirkkkov-pc/internal/winfs/authenticode"
	"github.com/mirkovedia/mirkkkov-pc/internal/winfs/reghive"
	winservices "github.com/mirkovedia/mirkkkov-pc/internal/winfs/services"
)

// Collector recolecta drivers no estándar del subárbol Services del hive SYSTEM.
type Collector struct {
	HivePath string
	// Verify comprueba la firma del binario del driver. Se inyecta para que
	// los tests no dependan de wintrust.dll.
	Verify authenticode.Verifier
}

// New crea el colector apuntando al hive SYSTEM dado (una copia legible).
func New(systemHivePath string) *Collector {
	return &Collector{HivePath: systemHivePath, Verify: authenticode.Verify}
}

func (c *Collector) Name() string  { return "services" }
func (c *Collector) Priority() int { return collector.PriorityRegistry }

// driverArtifact es lo que se serializa: el servicio tal como está en el
// registro más la firma del binario al que apunta. Los campos del servicio
// quedan al tope del JSON, que es donde el motor de severidad los busca.
type driverArtifact struct {
	winservices.DriverService
	Signature authenticode.Result `json:"Signature"`
}

func (c *Collector) Collect(ctx context.Context) ([]collector.Artifact, error) {
	data, err := os.ReadFile(c.HivePath)
	if err != nil {
		return nil, err
	}
	h, err := reghive.Open(data)
	if err != nil {
		return nil, err
	}
	root, err := h.OpenKey(`ControlSet001\Services`)
	if err != nil {
		root, err = h.OpenKey(`ControlSet002\Services`)
		if err != nil {
			return nil, err
		}
	}
	all, err := winservices.ParseServices(root)
	if err != nil {
		return nil, err
	}
	artifacts := make([]collector.Artifact, 0)
	for _, s := range all {
		select {
		case <-ctx.Done():
			return artifacts, ctx.Err()
		default:
		}
		if !winservices.IsNonMicrosoftDriver(s) {
			continue
		}
		b, _ := json.Marshal(c.enrich(s))
		artifacts = append(artifacts, collector.Artifact{
			Type:      "service_driver",
			Source:    s.ImagePath,
			Data:      b,
			Collected: time.Now(),
		})
	}
	return artifacts, nil
}

// enrich adjunta la firma del binario del driver. La ruta se verifica ya
// normalizada (\SystemRoot\ y \??\ resueltos): es la ruta real en disco.
func (c *Collector) enrich(s winservices.DriverService) driverArtifact {
	art := driverArtifact{DriverService: s}
	if c.Verify != nil {
		art.Signature = c.Verify(winservices.NormalizeImagePath(s.ImagePath))
	} else {
		art.Signature = authenticode.Result{Status: authenticode.StatusUnknown}
	}
	return art
}
