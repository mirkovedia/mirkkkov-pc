//go:build windows

// Package sysinfo lee los datos de contexto de la máquina que van al reporte:
// versión de Windows y fecha de instalación. No son evidencia forense, son lo
// que permite leer la evidencia: un Prefetch vacío significa otra cosa en una
// instalación de hace tres días que en una de hace tres años.
package sysinfo

import (
	"fmt"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

const currentVersionKey = `SOFTWARE\Microsoft\Windows NT\CurrentVersion`

// Build devuelve la versión de Windows en la forma "10.0.26200 (25H2)". El
// número sale de RtlGetVersion, que a diferencia de GetVersionEx no miente
// según el manifiesto del ejecutable; la etiqueta comercial sale del registro
// y puede faltar.
func Build() string {
	v := windows.RtlGetVersion()
	build := fmt.Sprintf("%d.%d.%d", v.MajorVersion, v.MinorVersion, v.BuildNumber)
	if label := displayVersion(); label != "" {
		return build + " (" + label + ")"
	}
	return build
}

func displayVersion() string {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, currentVersionKey, registry.QUERY_VALUE)
	if err != nil {
		return ""
	}
	defer k.Close()
	// DisplayVersion ("24H2") existe desde 20H2; ReleaseId ("2004") antes.
	if s, _, err := k.GetStringValue("DisplayVersion"); err == nil && s != "" {
		return s
	}
	if s, _, err := k.GetStringValue("ReleaseId"); err == nil {
		return s
	}
	return ""
}

// InstallDate devuelve la fecha de instalación de Windows según el registro.
// ok es false si el valor no existe o no se pudo leer.
func InstallDate() (t time.Time, ok bool) {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, currentVersionKey, registry.QUERY_VALUE)
	if err != nil {
		return time.Time{}, false
	}
	defer k.Close()
	// InstallDate es un REG_DWORD con segundos Unix. InstallTime (REG_QWORD
	// FILETIME) existe en versiones nuevas pero el DWORD sigue presente.
	unix, _, err := k.GetIntegerValue("InstallDate")
	if err != nil || unix == 0 {
		return time.Time{}, false
	}
	return time.Unix(int64(unix), 0).UTC(), true
}
