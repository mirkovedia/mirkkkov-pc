package report

import "time"

// MachineInfo describe el estado de la máquina examinada.
type MachineInfo struct {
	OS            string   `json:"os"`
	Build         string   `json:"build"`
	UptimeMinutes int      `json:"uptimeMinutes"`
	Elevated      bool     `json:"elevated"`
	VM            bool     `json:"vm"`
	VMReasons     []string `json:"vmReasons,omitempty"`
	// InstallDate es la fecha de instalación de Windows según el registro.
	// Es contexto para leer el resto: una instalación de hace tres días
	// explica por sí sola un Prefetch casi vacío y un USN journal nuevo.
	InstallDate *time.Time `json:"installDate,omitempty"`
}

// Finding es un hallazgo forense individual.
type Finding struct {
	ID         string     `json:"id"`
	Category   string     `json:"category"` // ANTI_FORENSIC | EXECUTION | PERSISTENCE | EMULATOR | KNOWN_CHEAT
	Severity   string     `json:"severity"` // INFO | LOW | MEDIUM | HIGH | CRITICAL
	Confidence float64    `json:"confidence"`
	Title      string     `json:"title"`
	Evidence   string     `json:"evidence"`
	Artifact   string     `json:"artifact"`
	Timestamp  *time.Time `json:"timestamp,omitempty"`
}

// CollectorRun deja constancia de cómo le fue a cada colector. Sin esto un
// escaneo parcial se ve idéntico a uno completo, y cuando a alguien le falla
// una fuente no hay forma de saber cuál ni por qué.
type CollectorRun struct {
	Name       string `json:"name"`
	Artifacts  int    `json:"artifacts"`
	DurationMs int64  `json:"durationMs"`
	Error      string `json:"error,omitempty"`
}

// Niveles posibles del veredicto global.
const (
	LevelLimpio          = "LIMPIO"
	LevelSospechoso      = "SOSPECHOSO"
	LevelEvidenciaFuerte = "EVIDENCIA_FUERTE"
	// LevelIncompleto se usa cuando no se halló evidencia PERO algún colector
	// falló: el agente no puede afirmar "limpio" sobre lo que no llegó a ver.
	LevelIncompleto = "INCOMPLETO"
)

// Estados posibles del escaneo.
const (
	StatusComplete = "COMPLETE"
	// StatusAborted indica que el contexto se agotó o se canceló antes de
	// terminar: algunos colectores pueden haber devuelto resultados parciales.
	StatusAborted = "ABORTED"
	StatusError   = "ERROR"
)

// Verdict es la conclusión global del escaneo.
type Verdict struct {
	Level            string   `json:"level"`
	Summary          string   `json:"summary"`
	Reasons          []string `json:"reasons,omitempty"`
	FailedCollectors []string `json:"failedCollectors,omitempty"`
}

// Report es el reporte firmado con cadena de custodia.
//
// Nonce y Pubkey van dentro del reporte para que sea verificable sin
// servidor: con ellos cualquiera puede recomputar la cadena de hashes desde
// H_0 = SHA256(nonce) y comprobar la firma Ed25519 del root (ver Verify en
// verify.go). Sin esos dos campos la firma era un número que nadie podía
// chequear.
type Report struct {
	SessionID    string         `json:"sessionId"`
	Platform     string         `json:"platform"` // "windows"
	AgentVersion string         `json:"agentVersion"`
	StartedAt    time.Time      `json:"startedAt"`
	EndedAt      time.Time      `json:"endedAt"`
	ConsentAt    time.Time      `json:"consentAt"`
	Machine      MachineInfo    `json:"machine"`
	Collectors   []CollectorRun `json:"collectors,omitempty"`
	Findings     []Finding      `json:"findings"`
	Verdict      Verdict        `json:"verdict"`
	Nonce        string         `json:"nonce"`
	Pubkey       string         `json:"pubkey"`
	HashChain    []string       `json:"hashChain"`
	Signature    string         `json:"signature"`
	Status       string         `json:"status"` // COMPLETE | ABORTED | ERROR
}
