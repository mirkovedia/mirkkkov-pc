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
	"github.com/mirkovedia/mirkkkov-pc/internal/winfs/vss"
)

// RunLive arma los colectores reales (tomando hives desde un snapshot VSS) y
// ejecuta el flujo completo con consentimiento ya otorgado por el CLI.
func RunLive(ctx context.Context, opts Options, up transport.Uploader) (report.Report, error) {
	systemHive := `C:\Windows\System32\config\SYSTEM`
	softwareHive := `C:\Windows\System32\config\SOFTWARE`
	amcacheHive := `C:\Windows\appcompat\Programs\Amcache.hve`
	securityLog := `C:\Windows\System32\winevt\Logs\Security.evtx`
	systemLog := `C:\Windows\System32\winevt\Logs\System.evtx`
	taskSchedLog := `C:\Windows\System32\winevt\Logs\Microsoft-Windows-TaskScheduler%4Operational.evtx`

	// Intentar un snapshot VSS para leer hives en uso; si falla, degradar a
	// los paths en vivo (se registrará como colector con posible error).
	if snap, err := vss.Create(`C:\`); err == nil {
		defer snap.Close()
		systemHive = vss.PathIn(snap, `Windows\System32\config\SYSTEM`)
		softwareHive = vss.PathIn(snap, `Windows\System32\config\SOFTWARE`)
		amcacheHive = vss.PathIn(snap, `Windows\appcompat\Programs\Amcache.hve`)
		securityLog = vss.PathIn(snap, `Windows\System32\winevt\Logs\Security.evtx`)
		systemLog = vss.PathIn(snap, `Windows\System32\winevt\Logs\System.evtx`)
		taskSchedLog = vss.PathIn(snap, `Windows\System32\winevt\Logs\Microsoft-Windows-TaskScheduler%4Operational.evtx`)
	}

	collectors := []collector.Collector{
		prefetch.New(),
		usncol.New(),
		mftcol.New(),
		deletedcol.New(),
		bam.New(systemHive),
		shimcache.New(systemHive),
		amcache.New(amcacheHive),
		servicescol.New(systemHive),
		schedulercol.New(`C:\Windows\System32\Tasks`, softwareHive),
		eventlogcol.New(securityLog, systemLog, taskSchedLog, systemHive, softwareHive),
	}
	return runWithCollectors(ctx, opts, up, collectors, true)
}
