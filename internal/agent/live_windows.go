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
	// Cada hive degrada por separado: copia raw, después snapshot VSS, después
	// la ruta en vivo. Antes era todo o nada, y un SOFTWARE ilegible tiraba
	// también un SYSTEM que se había copiado bien.
	specs := []struct {
		name, live, rel string
		dst             *string
	}{
		{"SYSTEM", liveSystemHive, `Windows\System32\config\SYSTEM`, &hives.system},
		{"SOFTWARE", liveSoftwareHive, `Windows\System32\config\SOFTWARE`, &hives.software},
		{"Amcache.hve", liveAmcacheHive, `Windows\appcompat\Programs\Amcache.hve`, &hives.amcache},
	}
	stage, stageErr := lockedfile.NewStage()
	if stageErr != nil {
		note("hives: no se pudo crear el directorio temporal: %v", stageErr)
	} else {
		// El stage vive hasta que termina el escaneo.
		defer stage.Close()
	}
	var pending []int
	for i, s := range specs {
		if stage != nil {
			copied, err := stage.Copy(s.live)
			if err == nil {
				*s.dst = copied
				note("hive %s: copia por acceso raw NTFS", s.name)
				continue
			}
			note("hive %s: la copia raw falló: %v", s.name, err)
		}
		pending = append(pending, i)
	}
	if len(pending) > 0 {
		snap, vssErr := vss.Create(`C:\`)
		if vssErr != nil {
			note("hives: el snapshot VSS falló: %v", vssErr)
		} else {
			defer snap.Close()
		}
		for _, i := range pending {
			if vssErr == nil {
				*specs[i].dst = vss.PathIn(snap, specs[i].rel)
				note("hive %s: snapshot VSS", specs[i].name)
			} else {
				note("hive %s: se usa la ruta en vivo; sus colectores van a fallar si está tomado", specs[i].name)
			}
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
