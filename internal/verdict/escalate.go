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
	// artifactOf y no a.Source: ver su comentario.
	name := artifactOf(a)
	strong := fsforensic.HasStrongMarker(name)
	if !strong && !fsforensic.IsSuspiciousName(name) {
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
	case "autorun", "process":
		return unsignedBinaryRule(a, r)
	case "macro_tool":
		return macroToolRule(a, r)
	case "ifeo_debugger":
		return ifeoRule(a, r)
	case "eventlog.time_changed":
		return timeChangeRule(a, r)
	case "amcache":
		return knownCheatRule(a, r)
	}
	return r
}

// userWritableLocations son rutas donde un usuario sin privilegios puede
// dejar un ejecutable: es donde vive lo que se descargó y se corrió sin
// instalar nada. Todo el perfil cuenta, no solo AppData.
var userWritableLocations = []string{`c:\users\`, `\programdata\`, `\temp\`, `\tmp\`}

// unsignedBinaryRule escala los artefactos neutros que llevan firma
// (autoruns y procesos) cuando el binario no la tiene Y está en una ruta
// escribible por el usuario. El peso depende de qué es:
//
//   - un proceso → LOW. Correr algo sin firma desde el perfil es lo que hace
//     un cheat, pero también TLauncher, un launcher indie, uv, bun o cualquier
//     script de pip: la primera calibración real lo tenía en MEDIUM y dos de
//     esos alcanzaban para un SOSPECHOSO sobre una máquina limpia. Queda
//     visible para quien revisa, sin mover el veredicto por sí solo.
//   - un autorun → MEDIUM. Que además arranque con Windows es más raro y
//     más deliberado.
//
// Sin firma fuera del perfil (Program Files) no dice nada: go.exe y las
// utilidades de Git tampoco están firmadas. Firmado o desconocido, neutro.
func unsignedBinaryRule(a collector.Artifact, r Rule) Rule {
	var payload struct {
		Path      string `json:"path"`
		Signature signaturePayload
	}
	if err := json.Unmarshal(a.Data, &payload); err != nil || !payload.Signature.untrusted() {
		return r
	}
	lower := strings.ToLower(payload.Path)
	writable := false
	for _, loc := range userWritableLocations {
		if strings.Contains(lower, loc) {
			writable = true
			break
		}
	}
	if !writable {
		return r
	}
	if a.Type == "autorun" {
		r.Severity = SevMedium
		r.Confidence = 0.5
		return r
	}
	r.Severity = SevLow
	r.Confidence = 0.3
	return r
}

// macroToolRule baja a INFO el software de periféricos que trae macros pero
// que tiene cualquiera (Logitech, Razer, Corsair). Las herramientas cuyo
// único fin es automatizar entrada conservan el LOW base.
func macroToolRule(a collector.Artifact, r Rule) Rule {
	var payload struct {
		Weight string `json:"weight"`
	}
	if err := json.Unmarshal(a.Data, &payload); err != nil {
		return r
	}
	if payload.Weight == "info" {
		r.Severity = SevInfo
		r.Confidence = 0.0
	}
	return r
}

// knownDebuggers son depuradores IFEO que instalan herramientas legítimas
// (Visual Studio, Sysinternals). Duplicado a propósito con el colector: el
// motor es puro y no importa paquetes de colectores.
var knownDebuggers = []string{"vsjitdebugger", "procdump", "gflags", "windbg"}

// ifeoRule baja a INFO los depuradores de herramientas de desarrollo.
func ifeoRule(a collector.Artifact, r Rule) Rule {
	var payload struct {
		Debugger string `json:"debugger"`
	}
	if err := json.Unmarshal(a.Data, &payload); err != nil {
		return r
	}
	lower := strings.ToLower(payload.Debugger)
	for _, k := range knownDebuggers {
		if strings.Contains(lower, k) {
			r.Severity = SevInfo
			r.Confidence = 0.0
			return r
		}
	}
	return r
}

// timeChangeRule baja a INFO los cambios de hora que hace el propio sistema.
func timeChangeRule(a collector.Artifact, r Rule) Rule {
	var payload struct {
		Legit bool `json:"legit"`
	}
	if err := json.Unmarshal(a.Data, &payload); err != nil {
		return r
	}
	if payload.Legit {
		r.Severity = SevInfo
		r.Confidence = 0.0
	}
	return r
}

// knownCheatRule convierte una entrada de Amcache cuyo SHA-1 figura en la
// lista de cheats conocidos en un hallazgo CRITICAL de categoría KNOWN_CHEAT.
// Amcache conserva el hash aunque el archivo ya no exista: es la única
// fuente que identifica un binario borrado sin ambigüedad.
func knownCheatRule(a collector.Artifact, r Rule) Rule {
	var payload struct {
		SHA1 string `json:"sha1"`
	}
	if err := json.Unmarshal(a.Data, &payload); err != nil || payload.SHA1 == "" {
		return r
	}
	if _, ok := KnownCheat(payload.SHA1); ok {
		return Rule{Category: CatKnownCheat, Severity: SevCritical, Confidence: 0.95}
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

// signaturePayload es la firma que los colectores de Fase 8 adjuntan a sus
// artefactos. Status vacío significa "este artefacto no trae firma" (colector
// viejo o campo ausente) y se trata igual que unknown.
type signaturePayload struct {
	Status string
	Signer string
}

func (s signaturePayload) signed() bool    { return s.Status == "signed" }
func (s signaturePayload) untrusted() bool { return s.Status == "unsigned" || s.Status == "invalid" }

// scheduledTaskRule baja a INFO las tareas propias de Windows (el sistema trae
// decenas marcadas como ocultas) y las que lanzan un ejecutable con firma
// válida: una tarea oculta de un actualizador firmado es rutina. Una oculta
// cuyo ejecutable no tiene firma conserva el MEDIUM base.
func scheduledTaskRule(a collector.Artifact, r Rule) Rule {
	var payload struct {
		RelPath   string
		Signature signaturePayload
	}
	if err := json.Unmarshal(a.Data, &payload); err != nil {
		return r
	}
	if strings.HasPrefix(strings.ToLower(payload.RelPath), `microsoft\`) || payload.Signature.signed() {
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

// serviceDriverRule pondera un driver por su firma y por su ubicación:
//
//   - firma válida → INFO, esté donde esté. Un driver firmado por Wellbia en
//     C:\Windows es el anticheat de otro juego, no un rootkit.
//   - sin firma o firma inválida fuera de las rutas normales → HIGH. Windows
//     10+ no carga drivers de kernel sin firma salvo en modo de prueba, así
//     que uno registrado como servicio es una anomalía real.
//   - sin firma en una ruta normal → MEDIUM: raro, pero puede ser un resto
//     de un instalador viejo.
//   - firma desconocida (archivo borrado, API falló) → la heurística por
//     ruta de siempre: INFO en rutas normales, MEDIUM base fuera.
func serviceDriverRule(a collector.Artifact, r Rule) Rule {
	var payload struct {
		ImagePath string
		Signature signaturePayload
	}
	if err := json.Unmarshal(a.Data, &payload); err != nil {
		return r
	}
	if payload.Signature.signed() {
		r.Severity = SevInfo
		r.Confidence = 0.0
		return r
	}
	normalized := winservices.NormalizeImagePath(payload.ImagePath)
	normal := false
	for _, loc := range normalDriverLocations {
		if strings.Contains(normalized, loc) {
			normal = true
			break
		}
	}
	switch {
	case payload.Signature.untrusted() && !normal:
		r.Severity = SevHigh
		r.Confidence = 0.7
	case payload.Signature.untrusted() && normal:
		r.Severity = SevMedium
		r.Confidence = 0.6
	case normal:
		r.Severity = SevInfo
		r.Confidence = 0.0
	}
	return r
}
