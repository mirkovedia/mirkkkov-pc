// internal/verdict/escalate.go
package verdict

import (
	"encoding/json"
	"regexp"
	"strings"

	"github.com/mirkovedia/mirkkkov-pc/internal/collector"
	"github.com/mirkovedia/mirkkkov-pc/internal/winfs/fsforensic"
	winservices "github.com/mirkovedia/mirkkkov-pc/internal/winfs/services"
)

// suspiciousConfidence es la confianza que se fija cuando el nombre del
// artefacto matchea un marcador conocido.
const suspiciousConfidence = 0.8

// escalate ajusta la regla base según el contenido del artefacto: primero por
// detalle específico del tipo, después por nombre sospechoso.
func escalate(a collector.Artifact, base Rule) Rule {
	r := escalateByDetail(a, base)
	return escalateByName(a, r)
}

// escalateByName sube dos niveles si el Source matchea un marcador de
// fsforensic, con un tope que depende del peso de la evidencia:
//
//   - marcador fuerte (cheat, aimbot, ...): tope HIGH. CRITICAL se reserva a
//     los combos, porque un nombre feo por sí solo no es la afirmación más
//     grave que el motor puede hacer.
//   - marcador débil (token exacto: hook, esp, loader, ...): tope MEDIUM. Un
//     "run-hook.cmd" borrado es un script de desarrollo, no evidencia forense.
func escalateByName(a collector.Artifact, r Rule) Rule {
	strong := fsforensic.HasStrongMarker(a.Source)
	if !strong && !fsforensic.IsSuspiciousName(a.Source) {
		return r
	}
	cap := SevMedium
	if strong {
		cap = SevHigh
	}
	raised := bumpSeverity(r.Severity, 2)
	if severityRank(raised) > severityRank(cap) {
		raised = cap
	}
	// Nunca bajar: si la regla base ya era más grave, se respeta.
	if severityRank(raised) < severityRank(r.Severity) {
		raised = r.Severity
	}
	r.Severity = raised
	r.Confidence = suspiciousConfidence
	return r
}

// escalateByDetail aplica el ajuste específico de los tipos cuyo peso depende
// de un campo de su payload.
func escalateByDetail(a collector.Artifact, r Rule) Rule {
	switch a.Type {
	case "scheduled_task_desync":
		return desyncTaskRule(a, r)
	case "eventlog.desync":
		return eventDesyncRule(a, r)
	case "scheduled_task":
		return scheduledTaskRule(a, r)
	case "service_driver":
		return serviceDriverRule(a, r)
	case "eventlog.tamper_signal":
		return tamperSignalRule(a, r)
	}
	return r
}

// nonEvidenceTamperKinds son señales que NO prueban manipulación:
//   - log_unreadable: el log no se pudo abrir. TaskScheduler/Operational viene
//     deshabilitado por defecto en Windows, así que "no existe" es lo normal.
//   - dirty_flag / full_flag: banderas esperables en un snapshot VSS de un log
//     que estaba abierto y escribiéndose.
//
// Reportar "no pude verificar" como evidencia es justamente el error que hay
// que evitar en una herramienta que puede sancionar a alguien.
var nonEvidenceTamperKinds = map[string]bool{
	"log_unreadable": true,
	"dirty_flag":     true,
	"full_flag":      true,
}

// tamperSignalRule baja a INFO las señales que no distinguen manipulación de
// condiciones normales. chunk_crc_invalid, record_id_gap y truncated se
// mantienen en HIGH: esos sí implican edición binaria del archivo.
func tamperSignalRule(a collector.Artifact, r Rule) Rule {
	var payload struct {
		Kind string
	}
	if err := json.Unmarshal(a.Data, &payload); err != nil {
		return r
	}
	if nonEvidenceTamperKinds[payload.Kind] {
		r.Severity = SevInfo
		r.Confidence = 0.0
	}
	return r
}

// desyncTaskRule pondera la dirección de la desincronía XML-registro: cambia
// radicalmente lo que significa.
func desyncTaskRule(a collector.Artifact, r Rule) Rule {
	var payload struct {
		Kind    string
		RelPath string
	}
	if err := json.Unmarshal(a.Data, &payload); err != nil {
		return r // payload ilegible: se queda con la regla base
	}
	switch payload.Kind {
	case "hive_only":
		if strings.HasPrefix(strings.ToLower(payload.RelPath), `microsoft\`) || isWindowsManagedRootTask(payload.RelPath) {
			// Windows guarda varias de sus tareas propias SOLO en el
			// registro, sin XML en disco. Se verificó sobre una máquina real:
			// el escaneo enumeró el árbol completo sin un solo error de
			// permisos y estas tareas igual no tenían archivo. Para el
			// subárbol Microsoft\ la señal no distingue un borrado
			// deliberado de cómo Windows guarda sus cosas.
			r.Severity = SevInfo
			r.Confidence = 0.0
			break
		}
		// Fuera de Microsoft\ sí es señal: el XML fue borrado pero la entrada
		// sigue en TaskCache, o sea que alguien borró el archivo visible y no
		// pudo limpiar el registro.
		r.Severity = SevHigh
		r.Confidence = 0.8
	case "file_only":
		// El XML existe sin entrada en el registro: puede ser una tarea
		// recién creada (condición de carrera legítima).
		r.Severity = SevLow
		r.Confidence = 0.3
	}
	return r
}

// perUserTaskSuffix matchea los nombres de tarea que terminan en un SID de
// usuario, con o sin sufijo numérico: "…-S-1-5-21-…-1001" y
// "PostponeDeviceSetupToast_S-1-5-21-…-1001_0". Windows y sus componentes
// (OneDrive, Optimize Start Menu Cache Files, DeviceSetupManager) las crean y
// borran por cuenta propia para cada usuario.
var perUserTaskSuffix = regexp.MustCompile(`(?i)[-_]S-1-5-(?:18|19|20|21-\d+-\d+-\d+-\d+)(?:_\d+)?$`)

// windowsManagedRootTasks son tareas que Windows crea en la raíz del árbol de
// tareas, fuera de Microsoft\, y cuya entrada en TaskCache puede existir sin
// XML en disco sin que nadie las haya tocado. Se comparan por prefijo, en
// minúsculas.
var windowsManagedRootTasks = []string{
	"postponedevicesetuptoast",
	"user_feed_synchronization-",
	"optimize start menu cache files-",
	"createexplorershellunelevatedtask",
	"microsoftedgeupdatetask",
	"onedrive ",
}

// isWindowsManagedRootTask reporta si la ruta relativa de una tarea es una de
// las que Windows administra por su cuenta en la raíz del árbol. Para ellas,
// "está en el registro pero no en disco" es un estado normal, no un borrado:
// el único CRITICAL del reporte real del 2026-08-05 fue exactamente esto.
func isWindowsManagedRootTask(relPath string) bool {
	lower := strings.ToLower(relPath)
	if strings.Contains(lower, `\`) {
		return false // solo tareas de la raíz
	}
	if perUserTaskSuffix.MatchString(lower) {
		return true
	}
	for _, p := range windowsManagedRootTasks {
		if strings.HasPrefix(lower, p) {
			return true
		}
	}
	return false
}

// nonEvidenceDesyncKinds son las direcciones de eventlog.desync que no pueden
// ser sanas: los Event Logs rotan, así que un servicio o tarea registrados
// hace meses nunca van a tener su evento de instalación disponible. La
// ausencia no prueba nada; se reporta para auditoría sin mover el veredicto.
var nonEvidenceDesyncKinds = map[string]bool{
	"task_no_register_log":   true,
	"service_no_install_log": true,
}

// eventDesyncRule baja a INFO las direcciones que no pueden ser sanas.
func eventDesyncRule(a collector.Artifact, r Rule) Rule {
	var payload struct {
		Kind string
	}
	if err := json.Unmarshal(a.Data, &payload); err != nil {
		return r
	}
	if nonEvidenceDesyncKinds[payload.Kind] {
		r.Severity = SevInfo
		r.Confidence = 0.0
	}
	return r
}

// scheduledTaskRule baja a INFO las tareas propias de Windows: el sistema trae
// decenas marcadas como ocultas y no son señal por sí solas.
func scheduledTaskRule(a collector.Artifact, r Rule) Rule {
	var payload struct {
		RelPath string
	}
	if err := json.Unmarshal(a.Data, &payload); err != nil {
		return r
	}
	if strings.HasPrefix(strings.ToLower(payload.RelPath), `microsoft\`) {
		r.Severity = SevInfo
		r.Confidence = 0.0
	}
	return r
}

// normalDriverLocations son ubicaciones donde el software instalado deja sus
// drivers de forma legítima (antivirus, GPU, VPN, virtualización). Se comparan
// contra la ruta YA normalizada por services.NormalizeImagePath, que resuelve
// \SystemRoot\, \??\ y las rutas relativas a c:\windows\.
var normalDriverLocations = []string{
	`\program files\`,
	`\program files (x86)\`,
	`c:\windows\system32\`,
	`c:\windows\syswow64\`,
}

// serviceDriverRule baja a INFO los drivers en ubicaciones normales de
// instalación. La heurística de Fase 3C es por ruta, no por firma, así que sin
// este ajuste marca decenas de drivers legítimos en cualquier máquina real.
func serviceDriverRule(a collector.Artifact, r Rule) Rule {
	var payload struct {
		ImagePath string
	}
	if err := json.Unmarshal(a.Data, &payload); err != nil {
		return r
	}
	normalized := winservices.NormalizeImagePath(payload.ImagePath)
	for _, loc := range normalDriverLocations {
		if strings.Contains(normalized, loc) {
			r.Severity = SevInfo
			r.Confidence = 0.0
			return r
		}
	}
	return r
}
