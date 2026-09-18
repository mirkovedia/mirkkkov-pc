//go:build !windows

package lockedfile

import (
	"errors"
	"os"
)

// ErrUnsupported se devuelve fuera de Windows cuando la copia normal falla.
var ErrUnsupported = errors.New("lectura raw NTFS solo disponible en Windows")

// CopyTo copia src a dst con la copia normal; no hay camino raw fuera de Windows.
func CopyTo(src, dst string) error {
	data, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	return os.WriteFile(dst, data, 0o600)
}

// ReadFile lee src con la copia normal.
func ReadFile(src string) ([]byte, error) { return os.ReadFile(src) }
