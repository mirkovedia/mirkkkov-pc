//go:build windows

package ui

import (
	"os"
	"os/exec"
	"path/filepath"

	"golang.org/x/sys/windows"
)

// Reveal abre el explorador de Windows mostrando la ubicación de path.
//
// Si el archivo existe se lo deja seleccionado; si ya no está (el caso normal
// de un artefacto borrado recuperado del MFT) se abre el directorio que lo
// contenía, que sigue siendo información útil para quien revisa.
//
// La ruta viene de datos que controla quien es revisado, y este proceso
// corre elevado. Reveal nunca debe ejecutar nada ni salir a la red: por eso
// solo acepta discos locales y solo le pasa a explorer.exe algo que ya
// comprobó que es un directorio.
func Reveal(path string) error {
	if !RevealablePath(path) {
		return ErrNotRevealable
	}
	clean := filepath.Clean(path)
	if !onLocalDrive(clean) {
		return ErrNotRevealable
	}

	if _, err := os.Stat(clean); err == nil {
		// exec.Command no pasa por una shell, así que la ruta no puede
		// inyectar comandos por más rara que sea. "/select," MUESTRA el
		// elemento, nunca lo abre.
		// explorer.exe devuelve código 1 incluso cuando abre bien, así que
		// su código de salida no se interpreta como fallo.
		_ = exec.Command("explorer.exe", "/select,"+clean).Run()
		return nil
	}

	// El archivo ya no está: se abre su carpeta, pero SOLO si es una carpeta.
	// os.Stat también tiene éxito sobre un archivo regular, y "explorer.exe
	// <archivo>" no muestra nada: lo abre con su asociación, o sea que
	// ejecuta un .exe, un .cmd o un .lnk. Con la ruta "C:\...\x.cmd\y" el
	// "padre" es un script elegido por quien es revisado, y un botón que
	// promete mostrar una carpeta terminaba ejecutándolo.
	dir := filepath.Dir(clean)
	info, err := os.Stat(dir)
	if err != nil || !info.IsDir() {
		return ErrNotRevealable
	}
	_ = exec.Command("explorer.exe", dir).Run()
	return nil
}

// onLocalDrive reporta si la ruta vive en un disco fijo o extraíble de esta
// máquina. Una unidad de red mapeada (Z:) tiene letra pero es un recurso SMB:
// tocarla tiene los mismos problemas que una ruta UNC.
func onLocalDrive(path string) bool {
	root, err := windows.UTF16PtrFromString(filepath.VolumeName(path) + `\`)
	if err != nil {
		return false
	}
	switch windows.GetDriveType(root) {
	case windows.DRIVE_FIXED, windows.DRIVE_REMOVABLE, windows.DRIVE_RAMDISK:
		return true
	}
	return false
}
