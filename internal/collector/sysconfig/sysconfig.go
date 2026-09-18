// Package sysconfig detecta configuraciones del sistema que apagan las
// fuentes forenses: Prefetch deshabilitado, carpeta Prefetch vacía en una
// instalación vieja, servicio de Event Log deshabilitado. Ninguna es un
// cheat; todas son lo que alguien toca cuando quiere que el resto de los
// colectores no encuentren nada.
package sysconfig

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"os"
	"path/filepath"
	"time"

	"github.com/mirkovedia/mirkkkov-pc/internal/collector"
	"github.com/mirkovedia/mirkkkov-pc/internal/winfs/reghive"
)

// Collector lee el hive SYSTEM y cuenta la carpeta Prefetch.
type Collector struct {
	SystemHive  string
	PrefetchDir string
	// InstallDate es la fecha de instalación de Windows; cero si no se
	// conoce. Sin ella no se afirma nada sobre un Prefetch vacío.
	InstallDate time.Time
}

// New crea el colector con las rutas reales.
func New(systemHive string, installDate time.Time) *Collector {
	return &Collector{SystemHive: systemHive, PrefetchDir: `C:\Windows\Prefetch`, InstallDate: installDate}
}

func (c *Collector) Name() string  { return "sysconfig" }
func (c *Collector) Priority() int { return collector.PriorityRegistry }

// Umbrales del Prefetch vacío: Windows conserva hasta 1024 archivos .pf y
// cualquier máquina en uso tiene cientos. Menos de minPrefetchFiles en una
// instalación de más de minInstallAge es alguien borrando la carpeta.
const (
	minPrefetchFiles = 10
	minInstallAge    = 14 * 24 * time.Hour
)

// PrefetchConfig es el estado del Prefetcher.
type PrefetchConfig struct {
	EnablePrefetcher uint32 `json:"enablePrefetcher"`
}

// PrefetchEmpty describe una carpeta Prefetch anormalmente vacía.
type PrefetchEmpty struct {
	Files       int       `json:"files"`
	InstallDate time.Time `json:"installDate"`
}

// ServiceStart es el modo de arranque de un servicio.
type ServiceStart struct {
	Service string `json:"service"`
	Start   uint32 `json:"start"` // 4 = deshabilitado
}

func (c *Collector) Collect(ctx context.Context) ([]collector.Artifact, error) {
	data, err := os.ReadFile(c.SystemHive)
	if err != nil {
		return nil, err
	}
	h, err := reghive.Open(data)
	if err != nil {
		return nil, err
	}
	now := time.Now()
	var arts []collector.Artifact
	emit := func(typ, source string, v any) {
		b, _ := json.Marshal(v)
		arts = append(arts, collector.Artifact{Type: typ, Source: source, Data: b, Collected: now})
	}

	prefetchEnabled := true
	if v, ok := dword(h, `Control\Session Manager\Memory Management\PrefetchParameters`, "EnablePrefetcher"); ok {
		if v == 0 {
			prefetchEnabled = false
			emit("config.prefetch_disabled", "EnablePrefetcher", PrefetchConfig{EnablePrefetcher: v})
		}
	}
	if prefetchEnabled && !c.InstallDate.IsZero() && now.Sub(c.InstallDate) > minInstallAge {
		if n, ok := countPrefetch(c.PrefetchDir); ok && n < minPrefetchFiles {
			emit("config.prefetch_empty", c.PrefetchDir, PrefetchEmpty{Files: n, InstallDate: c.InstallDate})
		}
	}
	if v, ok := dword(h, `Services\EventLog`, "Start"); ok && v == 4 {
		emit("config.eventlog_disabled", "EventLog", ServiceStart{Service: "EventLog", Start: v})
	}
	return arts, ctx.Err()
}

// dword lee un REG_DWORD bajo ControlSet001 (o ControlSet002 si el primero
// no existe), que es como el resto de los colectores resuelven
// CurrentControlSet sin leer el valor Select.
func dword(h *reghive.Hive, subpath, name string) (uint32, bool) {
	for _, cs := range []string{`ControlSet001\`, `ControlSet002\`} {
		key, err := h.OpenKey(cs + subpath)
		if err != nil {
			continue
		}
		raw, _, err := key.Value(name)
		if err != nil || len(raw) < 4 {
			return 0, false
		}
		return binary.LittleEndian.Uint32(raw[:4]), true
	}
	return 0, false
}

// countPrefetch cuenta los .pf. ok es false si la carpeta no se pudo leer:
// no saber no es lo mismo que estar vacía.
func countPrefetch(dir string) (int, bool) {
	matches, err := filepath.Glob(filepath.Join(dir, "*.pf"))
	if err != nil {
		return 0, false
	}
	if _, err := os.Stat(dir); err != nil {
		return 0, false
	}
	return len(matches), true
}
