//go:build windows

// internal/agent/live_windows.go
package agent

import (
	"context"
	"fmt"
	"time"

	"github.com/mirkovedia/mirkkkov-pc/internal/collector"
	"github.com/mirkovedia/mirkkkov-pc/internal/collector/amcache"
	"github.com/mirkovedia/mirkkkov-pc/internal/collector/bam"
	deletedcol "github.com/mirkovedia/mirkkkov-pc/internal/collector/deleted"
	"github.com/mirkovedia/mirkkkov-pc/internal/collector/emulator"
	eventlogcol "github.com/mirkovedia/mirkkkov-pc/internal/collector/eventlog"
	mftcol "github.com/mirkovedia/mirkkkov-pc/internal/collector/mft"
	"github.com/mirkovedia/mirkkkov-pc/internal/collector/persistence"
	"github.com/mirkovedia/mirkkkov-pc/internal/collector/prefetch"
	"github.com/mirkovedia/mirkkkov-pc/internal/collector/processes"
	schedulercol "github.com/mirkovedia/mirkkkov-pc/internal/collector/scheduler"
	servicescol "github.com/mirkovedia/mirkkkov-pc/internal/collector/services"
	"github.com/mirkovedia/mirkkkov-pc/internal/collector/shimcache"
	"github.com/mirkovedia/mirkkkov-pc/internal/collector/sysconfig"
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

	// Cómo se accedió a los hives queda anotado en el reporte. En el primer
	// escaneo real sobre un runner cuatro colectores cayeron con "el archivo
	// está en uso" y no había forma de saber por qué habían fallado la copia
	// raw y el snapshot antes de llegar ahí.
	note := func(format string, args ...any) {
		opts.Diagnostics = append(opts.Diagnostics, fmt.Sprintf(format, args...))
	}
	stage, stageErr := lockedfile.NewStage()
	if stageErr == nil {
		// El stage vive hasta que termina el escaneo.
		defer stage.Close()
		var staged hivePaths
		if staged, stageErr = stageHives(stage); stageErr == nil {
			hives = staged
		}
	}

	if stageErr == nil {
		note("hives: copia por acceso raw NTFS")
	} else {
		note("hives: la copia raw falló: %v", stageErr)
		if snap, vssErr := vss.Create(`C:\`); vssErr == nil {
			defer snap.Close()
			hives = hivePaths{
				system:   vss.PathIn(snap, `Windows\System32\config\SYSTEM`),
				software: vss.PathIn(snap, `Windows\System32\config\SOFTWARE`),
				amcache:  vss.PathIn(snap, `Windows\appcompat\Programs\Amcache.hve`),
			}
			note("hives: snapshot VSS")
		} else {
			note("hives: el snapshot VSS falló: %v", vssErr)
			note("hives: se usan las rutas en vivo; los colectores de registro van a fallar")
		}
	}

	var installDate time.Time
	if opts.Machine.InstallDate != nil {
		installDate = *opts.Machine.InstallDate
	}
	usn := usncol.New()
	usn.InstallDate = installDate

	collectors := []collector.Collector{
		// Volátil: lo que corre ahora desaparece al cerrar la ventana.
		processes.New(),
		// Registro y configuración.
		bam.New(hives.system),
		shimcache.New(hives.system),
		amcache.New(hives.amcache),
		servicescol.New(hives.system),
		persistence.New(hives.software),
		emulator.New(hives.software),
		sysconfig.New(hives.system, installDate),
		// Disco.
		prefetch.New(),
		usn,
		mftcol.New(),
		deletedcol.New(),
		schedulercol.New(`C:\Windows\System32\Tasks`, hives.software),
		eventlogcol.New(liveSecurityLog, liveSystemLog, liveTaskSchedLog, hives.system, hives.software),
	}
	return runWithCollectors(ctx, opts, up, collectors, true)
}

// stageHives copia los tres hives al stage. Es todo o nada: mezclar un hive
// copiado con uno del snapshot complica el diagnóstico sin ganar nada.
func stageHives(stage *lockedfile.Stage) (hivePaths, error) {
	var out hivePaths
	var err error
	if out.system, err = stage.Copy(liveSystemHive); err != nil {
		return hivePaths{}, fmt.Errorf("hive SYSTEM: %w", err)
	}
	if out.software, err = stage.Copy(liveSoftwareHive); err != nil {
		return hivePaths{}, fmt.Errorf("hive SOFTWARE: %w", err)
	}
	if out.amcache, err = stage.Copy(liveAmcacheHive); err != nil {
		return hivePaths{}, fmt.Errorf("hive Amcache.hve: %w", err)
	}
	return out, nil
}
