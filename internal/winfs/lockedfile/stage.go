package lockedfile

import (
	"os"
	"path/filepath"
)

// stagePrefix identifica los directorios temporales del agente, para poder
// limpiar los que dejó una ejecución anterior que murió a mitad de camino.
const stagePrefix = "mirkkkov-"

// Stage es un directorio temporal con copias de los archivos bloqueados que
// los colectores van a leer. Cumple el rol que antes tenía el snapshot VSS:
// un lugar del que se puede leer sin pelear con el sistema. A diferencia del
// snapshot, si el proceso muere lo que queda son archivos comunes en %TEMP%,
// que la próxima ejecución borra.
type Stage struct {
	dir string
}

// NewStage crea el directorio temporal y borra los restos de ejecuciones
// anteriores.
func NewStage() (*Stage, error) {
	cleanStale()
	dir, err := os.MkdirTemp("", stagePrefix+"*")
	if err != nil {
		return nil, err
	}
	return &Stage{dir: dir}, nil
}

// Copy copia src al stage y devuelve la ruta de la copia. Si falla, no deja
// un archivo a medias que un colector pudiera parsear como hive truncado.
func (s *Stage) Copy(src string) (string, error) {
	dst := filepath.Join(s.dir, filepath.Base(src))
	if err := CopyTo(src, dst); err != nil {
		os.Remove(dst)
		return "", err
	}
	return dst, nil
}

// Dir devuelve el directorio del stage.
func (s *Stage) Dir() string { return s.dir }

// Close borra el directorio y todo lo copiado.
func (s *Stage) Close() error {
	if s == nil || s.dir == "" {
		return nil
	}
	err := os.RemoveAll(s.dir)
	s.dir = ""
	return err
}

// cleanStale borra directorios de stage de ejecuciones anteriores. Errores
// aquí no importan: es limpieza oportunista.
func cleanStale() {
	entries, err := os.ReadDir(os.TempDir())
	if err != nil {
		return
	}
	for _, e := range entries {
		if e.IsDir() && len(e.Name()) > len(stagePrefix) && e.Name()[:len(stagePrefix)] == stagePrefix {
			_ = os.RemoveAll(filepath.Join(os.TempDir(), e.Name()))
		}
	}
}
