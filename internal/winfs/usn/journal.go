package usn

import (
	"errors"
	"time"
)

// ErrJournalNotActive indica que el volumen no tiene USN journal: fue
// borrado (fsutil usn deletejournal) o nunca se creó. En un Windows normal
// el journal de C: existe siempre, así que su ausencia es en sí una señal.
var ErrJournalNotActive = errors.New("el USN journal no está activo en el volumen")

// JournalInfo son los metadatos del journal de un volumen.
type JournalInfo struct {
	ID       uint64    `json:"journalId"`
	Created  time.Time `json:"created"`
	FirstUsn int64     `json:"firstUsn"`
	NextUsn  int64     `json:"nextUsn"`
}

// Umbrales de Recreated.
const (
	// recreatedMinAge: un journal creado en la primera semana de vida del
	// sistema es el que dejó la instalación (o un chkdsk temprano).
	recreatedMinAge = 7 * 24 * time.Hour
	// recreatedWindow: pasado un mes, la recreación ya no explica lo que el
	// escaneo ve hoy y se vuelve indistinguible de otras causas.
	recreatedWindow = 30 * 24 * time.Hour
)

// Recreated reporta si el journal parece haber sido borrado y creado de
// nuevo después de la instalación de Windows: nació bastante después que el
// sistema y hace poco. Sin fecha de instalación no se afirma nada.
func Recreated(created, installDate, now time.Time) bool {
	if created.IsZero() || installDate.IsZero() {
		return false
	}
	return created.Sub(installDate) > recreatedMinAge && now.Sub(created) < recreatedWindow
}
