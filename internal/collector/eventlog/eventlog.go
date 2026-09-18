package eventlog

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"time"

	"github.com/mirkovedia/mirkkkov-pc/internal/collector"
	"github.com/mirkovedia/mirkkkov-pc/internal/winfs/evtx"
	"github.com/mirkovedia/mirkkkov-pc/internal/winfs/reghive"
	winscheduler "github.com/mirkovedia/mirkkkov-pc/internal/winfs/scheduler"
	winservices "github.com/mirkovedia/mirkkkov-pc/internal/winfs/services"
)

// Collector recolecta y correlaciona Event Logs (.evtx).
type Collector struct {
	SecurityPath  string
	SystemPath    string
	TaskSchedPath string
	SystemHive    string
	SoftwareHive  string
}

func New(securityPath, systemPath, taskSchedPath, systemHive, softwareHive string) *Collector {
	return &Collector{
		SecurityPath:  securityPath,
		SystemPath:    systemPath,
		TaskSchedPath: taskSchedPath,
		SystemHive:    systemHive,
		SoftwareHive:  softwareHive,
	}
}

func (c *Collector) Name() string  { return "eventlog" }
func (c *Collector) Priority() int { return collector.PriorityDisk }

func (c *Collector) Collect(ctx context.Context) ([]collector.Artifact, error) {
	arts := make([]collector.Artifact, 0)

	// Parsear los tres logs; un log ilegible no aborta los demás.
	secLog := c.openLog(c.SecurityPath, "Security", &arts)
	sysLog := c.openLog(c.SystemPath, "System", &arts)
	taskLog := c.openLog(c.TaskSchedPath, "TaskScheduler", &arts)

	logsCleared := false

	for _, log := range []*evtx.Log{secLog, sysLog, taskLog} {
		if log == nil {
			continue
		}
		for _, ts := range log.Tamper {
			arts = appendJSON(arts, "eventlog.tamper_signal", ts.Kind, ts)
		}
		for _, r := range log.Records {
			// Un .evtx real puede traer cientos de miles de records: se
			// respeta el timeout global igual que el resto de colectores.
			select {
			case <-ctx.Done():
				return arts, ctx.Err()
			default:
			}
			switch r.EventID {
			case 4624, 4634, 6005, 6006, 6008:
				arts = appendJSON(arts, "eventlog.session_timeline", r.Channel, timelineEntry(r))
			case 1102, 104:
				logsCleared = true
				arts = appendJSON(arts, "eventlog.log_cleared", r.Channel, clearEntry(r))
			case 4616:
				if r.Channel == "Security" {
					arts = appendJSON(arts, "eventlog.time_changed", r.Channel, timeChangeEntry(r))
				}
			}
		}
	}

	installs := collectInstalls(sysLog)
	taskEvents := collectTaskEvents(taskLog)
	curServices := c.currentNonStandardServices()
	curTasks := c.currentNonStandardTasks()

	for _, d := range CrossCheck(installs, curServices, taskEvents, curTasks, logsCleared) {
		arts = appendJSON(arts, "eventlog.desync", d.Subject, d)
	}
	return arts, nil
}

// openLog abre un .evtx; si falla, emite un artifact de error y devuelve nil.
func (c *Collector) openLog(path, channel string, arts *[]collector.Artifact) *evtx.Log {
	if path == "" {
		return nil
	}
	log, err := evtx.Open(path, channel)
	if err != nil {
		*arts = appendJSON(*arts, "eventlog.tamper_signal", channel,
			evtx.TamperSignal{Kind: "log_unreadable", Detail: err.Error()})
		return nil
	}
	return log
}

type timeline struct {
	Time    time.Time `json:"time"`
	EventID uint16    `json:"event_id"`
	User    string    `json:"user,omitempty"`
	Logon   string    `json:"logon_type,omitempty"`
}

func timelineEntry(r evtx.Record) timeline {
	return timeline{Time: r.Timestamp, EventID: r.EventID, User: r.Fields["TargetUserName"], Logon: r.Fields["LogonType"]}
}

type clear struct {
	Time    time.Time `json:"time"`
	Channel string    `json:"channel"`
	By      string    `json:"cleared_by,omitempty"`
}

func clearEntry(r evtx.Record) clear {
	return clear{Time: r.Timestamp, Channel: r.Fields["Channel"], By: r.Fields["SubjectUserName"]}
}

// timeChange es un evento 4616: alguien cambió la hora del sistema. Es la
// contraparte del timestomping: para fabricar fechas viejas en archivos
// nuevos hace falta mover el reloj o editar los timestamps directamente.
type timeChange struct {
	Time     time.Time `json:"time"`
	Process  string    `json:"process,omitempty"`
	Previous time.Time `json:"previous,omitempty"`
	New      time.Time `json:"new,omitempty"`
	// Legit marca los cambios que hace el propio sistema: el servicio de
	// hora (svchost/W32Time) y las herramientas de sincronización de VM.
	// Ocurren varias veces al día y no dicen nada.
	Legit bool `json:"legit"`
}

// legitTimeChangers son los procesos que ajustan la hora por su cuenta.
var legitTimeChangers = []string{"svchost.exe", "w32tm", "w32time", "vmtoolsd", "vboxservice", "prl_tools", "lsass.exe", "wininit.exe"}

// timeChangeEntry arma el artefacto sin apostar a un índice de substitution:
// toma como proceso la primera cadena que termina en .exe y como fechas los
// dos primeros FILETIME que traiga el record.
func timeChangeEntry(r evtx.Record) timeChange {
	tc := timeChange{Time: r.Timestamp}
	for _, s := range r.StringValues() {
		if strings.HasSuffix(strings.ToLower(s), ".exe") {
			tc.Process = s
			break
		}
	}
	if times := r.TimeValues(); len(times) >= 2 {
		tc.Previous, tc.New = times[0], times[1]
	}
	lower := strings.ToLower(tc.Process)
	for _, p := range legitTimeChangers {
		if strings.Contains(lower, p) {
			tc.Legit = true
			break
		}
	}
	// Sin proceso identificado no se puede afirmar que fue manual; se marca
	// como no legítimo pero la regla base es LOW: solo pesa junto a un
	// timestomp en la misma ventana.
	return tc
}

func collectInstalls(log *evtx.Log) []InstallEvent {
	if log == nil {
		return nil
	}
	var out []InstallEvent
	for _, r := range log.Records {
		if r.EventID == 7045 {
			out = append(out, InstallEvent{ServiceName: r.Fields["ServiceName"], ImagePath: r.Fields["ImagePath"]})
		}
	}
	return out
}

func collectTaskEvents(log *evtx.Log) []TaskEvent {
	if log == nil {
		return nil
	}
	var out []TaskEvent
	for _, r := range log.Records {
		var action string
		switch r.EventID {
		case 106:
			action = "register"
		case 140:
			action = "update"
		case 141:
			action = "delete"
		default:
			continue
		}
		out = append(out, TaskEvent{Action: action, TaskName: r.Fields["TaskName"]})
	}
	return out
}

// currentNonStandardServices lee el hive SYSTEM y filtra a drivers no
// Microsoft. Si el hive no está disponible devuelve nil (la correlación de
// servicios se omite, pero el resto del colector sigue).
func (c *Collector) currentNonStandardServices() []winservices.DriverService {
	if c.SystemHive == "" {
		return nil
	}
	data, err := os.ReadFile(c.SystemHive)
	if err != nil {
		return nil
	}
	h, err := reghive.Open(data)
	if err != nil {
		return nil
	}
	root, err := h.OpenKey(`ControlSet001\Services`)
	if err != nil {
		if root, err = h.OpenKey(`ControlSet002\Services`); err != nil {
			return nil
		}
	}
	all, err := winservices.ParseServices(root)
	if err != nil {
		return nil
	}
	var out []winservices.DriverService
	for _, s := range all {
		if winservices.IsNonMicrosoftDriver(s) {
			out = append(out, s)
		}
	}
	return out
}

// currentNonStandardTasks lee TaskCache\Tree del hive SOFTWARE y filtra las
// tareas fuera de la carpeta Microsoft\ (las del sistema generan ruido).
func (c *Collector) currentNonStandardTasks() []winscheduler.CachedTask {
	if c.SoftwareHive == "" {
		return nil
	}
	data, err := os.ReadFile(c.SoftwareHive)
	if err != nil {
		return nil
	}
	h, err := reghive.Open(data)
	if err != nil {
		return nil
	}
	tree, err := h.OpenKey(`Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree`)
	if err != nil {
		return nil
	}
	all, err := winscheduler.WalkTaskCacheTree(tree)
	if err != nil {
		return nil
	}
	var out []winscheduler.CachedTask
	for _, t := range all {
		if !strings.HasPrefix(t.RelPath, `Microsoft\`) {
			out = append(out, t)
		}
	}
	return out
}

func appendJSON(arts []collector.Artifact, typ, source string, v any) []collector.Artifact {
	b, _ := json.Marshal(v)
	return append(arts, collector.Artifact{Type: typ, Source: source, Data: b, Collected: time.Now()})
}
