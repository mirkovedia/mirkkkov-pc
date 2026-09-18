//go:build windows

package vss

import (
	"fmt"
	"os/exec"
	"strings"
)

type wmicSnapshot struct {
	shadowID   string
	devicePath string
}

func (s *wmicSnapshot) DeviceObjectPath() string { return s.devicePath }

func (s *wmicSnapshot) Close() error {
	return exec.Command("vssadmin", "delete", "shadows", "/Shadow="+s.shadowID, "/quiet").Run()
}

// Create crea un shadow copy del volumen (ej. "C:\\") vía WMI.
//
// Primero por wmic; si no está (Windows 11 24H2 lo quitó de la instalación
// por defecto) se invoca la misma clase Win32_ShadowCopy por PowerShell/CIM,
// que sigue existiendo en todas las versiones.
func Create(volume string) (Snapshot, error) {
	id, err := createViaWmic(volume)
	if err != nil {
		var psErr error
		if id, psErr = createViaPowerShell(volume); psErr != nil {
			return nil, fmt.Errorf("crear shadow copy: wmic: %v; powershell: %w", err, psErr)
		}
	}
	device, err := resolveDevicePath(id)
	if err != nil {
		return nil, err
	}
	return &wmicSnapshot{shadowID: id, devicePath: device}, nil
}

func createViaWmic(volume string) (string, error) {
	out, err := exec.Command("wmic", "shadowcopy", "call", "create",
		"Volume="+volume).CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("wmic shadowcopy create falló: %w", err)
	}
	return parseShadowID(string(out))
}

// createViaPowerShell invoca Win32_ShadowCopy.Create por CIM e imprime solo
// el ShadowID. El volumen se pasa como argumento posicional, nunca
// interpolado en el script, para que una ruta rara no pueda inyectar nada.
func createViaPowerShell(volume string) (string, error) {
	script := `$r = Invoke-CimMethod -ClassName Win32_ShadowCopy -MethodName Create -Arguments @{Volume=$args[0]}; ` +
		`if ($r.ReturnValue -ne 0) { exit 1 }; Write-Output $r.ShadowID`
	out, err := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
		"-Command", script, volume).CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("Invoke-CimMethod Win32_ShadowCopy falló: %w (%s)", err, strings.TrimSpace(string(out)))
	}
	id := strings.TrimSpace(string(out))
	if !strings.HasPrefix(id, "{") || !strings.HasSuffix(id, "}") {
		return "", fmt.Errorf("ShadowID inesperado en la salida de PowerShell: %q", id)
	}
	return id, nil
}

// resolveDevicePath obtiene el DeviceObject del shadow copy vía vssadmin.
func resolveDevicePath(shadowID string) (string, error) {
	out, err := exec.Command("vssadmin", "list", "shadows", "/Shadow="+shadowID).CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("vssadmin list shadows falló: %w", err)
	}
	for _, line := range strings.Split(string(out), "\n") {
		if idx := strings.Index(line, `\\?\GLOBALROOT`); idx >= 0 {
			return strings.TrimSpace(line[idx:]), nil
		}
	}
	return "", fmt.Errorf("DeviceObject no encontrado para %s", shadowID)
}
