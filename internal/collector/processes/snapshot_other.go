//go:build !windows

package processes

import "errors"

// ErrUnsupported indica que la enumeración de procesos solo existe en Windows.
var ErrUnsupported = errors.New("enumeración de procesos solo disponible en Windows")

func snapshot() ([]Process, error) { return nil, ErrUnsupported }
