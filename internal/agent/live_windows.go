//go:build windows

// internal/agent/live_windows.go
package agent

import (
	"context"

	"github.com/mirkovedia/mirkkkov-pc/internal/collector"
	"github.com/mirkovedia/mirkkkov-pc/internal/collector/amcache"
	"github.com/mirkovedia/mirkkkov-pc/internal/collector/bam"
	deletedcol "github.com/mirkovedia/mirkkkov-pc/internal/collector/deleted"
	eventlogcol "github.com/mirkovedia/mirkkkov-pc/internal/collector/eventlog"
	mftcol "github.com/mirkovedia/mirkkkov-pc/internal/collector/mft"
	"github.com/mirkovedia/mirkkkov-pc/internal/collector/prefetch"
	schedulercol "github.com/mirkovedia/mirkkkov-pc/internal/collector/scheduler"
	servicescol "github.com/mirkovedia/mirkkkov-pc/internal/collector/services"
	"github.com/mirkovedia/mirkkkov-pc/internal/collector/shimcache"
	usncol "github.com/mirkovedia/mirkkkov-pc/internal/collector/usn"
	"github.com/mirkovedia/mirkkkov-pc/internal/report"
	"github.com/mirkovedia/mirkkkov-pc/internal/transport"
	"github.com/mirkovedia/mirkkkov-pc/internal/winfs/lockedfile"
	"github.com/mirkovedia/mirkkkov-pc/internal/winfs/vss"
)

// Rutas en vivo de las fuentes que necesitan los colectores.
const (
	liveSystemHive   = `C:\Windows\System32\config\SYSTEM`
	liveSoftwareHive = `C:\Windows\System32\config\SOFTWARE`
	liveAmcacheHive  = `C:\Windows\appcompat\Programs\Amcache.hve`
	liveSecurityLog  = `C:\Windows\System32\winevt\Logs\Security.evtx`
	liveSystemLog    = `C:\Windows\System32\winevt\Logs\System.evtx`
	liveTaskSchedLog = `C:\Windows\System32\winevt\Logs\Microsoft-Windows-TaskScheduler%4Operational.evtx`
)

// hivePaths son las rutas desde las que los colectores van a leer los hives.
type hivePaths struct {
	system, software, amcache string
}

// RunLive arma los colectores reales y ejecuta el flujo completo con
// consentimiento ya otorgado.
//
// Los hives del registro están tomados en exclusiva por el kernel. El camino
// principal los copia por acceso raw NTFS a un directorio temporal
// (lockedfile.Stage); si eso falla se intenta un snapshot VSS como antes, y
// si tampoco, se pasan las rutas en vivo para que cada colector registre su
// propio error. Los .evtx se leen en vivo: el servicio de Event Log los abre
// compartiendo lectura.
func RunLive(ctx context.Context, opts Options, up transport.Uploader) (report.Report, error) {
	hives := hivePaths{system: liveSystemHive, software: liveSoftwareHive, amcache: liveAmcacheHive}

	if stage, err := lockedfile.NewStage(); err == nil {
		defer stage.Close()
		if staged, ok := stageHives(stage); ok {
			hives = staged
		} else if snap, err := vss.Create(`C:\`); err == nil {
			defer snap.Close()
			hives = hivePaths{
				system:   vss.PathIn(snap, `Windows\System32\config\SYSTEM`),
				software: vss.PathIn(snap, `Windows\System32\config\SOFTWARE`),
				amcache:  vss.PathIn(snap, `Windows\appcompat\Programs\Amcache.hve`),
			}
		}
	}

	collectors := []collector.Collector{
		prefetch.New(),
		usncol.New(),
		mftcol.New(),
		deletedcol.New(),
		bam.New(hives.system),
		shimcache.New(hives.system),
		amcache.New(hives.amcache),
		servicescol.New(hives.system),
		schedulercol.New(`C:\Windows\System32\Tasks`, hives.software),
		eventlogcol.New(liveSecurityLog, liveSystemLog, liveTaskSchedLog, hives.system, hives.software),
	}
	return runWithCollectors(ctx, opts, up, collectors, true)
}

// stageHives copia los tres hives al stage. Es todo o nada: mezclar un hive
// copiado con uno del snapshot complica el diagnóstico sin ganar nada.
func stageHives(stage *lockedfile.Stage) (hivePaths, bool) {
	var out hivePaths
	var err error
	if out.system, err = stage.Copy(liveSystemHive); err != nil {
		return hivePaths{}, false
	}
	if out.software, err = stage.Copy(liveSoftwareHive); err != nil {
		return hivePaths{}, false
	}
	if out.amcache, err = stage.Copy(liveAmcacheHive); err != nil {
		return hivePaths{}, false
	}
	return out, true
}
