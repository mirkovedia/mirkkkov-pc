package ui

import (
	"errors"
	"strings"
)

// ErrNotRevealable indica que la ruta no corresponde a algo que el explorador
// pueda mostrar.
var ErrNotRevealable = errors.New("la ruta no apunta a un archivo del disco")

// RevealablePath reporta si una ruta tiene forma de ubicación real de un
// disco local.
//
// Muchos artefactos no son archivos: una tarea programada es "Microsoft\
// Windows\...", un servicio es un nombre del registro, y el MFT devuelve
// "\<sin-resolver>\..." cuando no logra reconstruir el directorio padre.
// Ofrecer un botón de carpeta para esos casos sería prometer algo que no se
// puede cumplir.
//
// Solo se aceptan rutas con letra de unidad. Las que empiezan con "\\" (UNC,
// "\\?\", "\\.\pipe\") se rechazan a propósito: la ruta la controla quien es
// revisado (alcanza un valor en HKCU\...\Run), y un os.Stat sobre
// "\\host\recurso\x" desde este proceso elevado abre una conexión SMB con
// autenticación NTLM automática hacia un host elegido por esa persona, además
// de congelar la ventana mientras dura el timeout. La interfaz trabaja sin
// red y el botón de carpeta no puede ser la excepción.
func RevealablePath(path string) bool {
	p := strings.TrimSpace(path)
	if p == "" {
		return false
	}
	if strings.Contains(p, "<sin-resolver>") {
		return false
	}
	// Rutas con salto de línea o nulos no vienen de un escaneo sano.
	if strings.ContainsAny(p, "\n\r\x00") {
		return false
	}
	if len(p) < 3 || p[1] != ':' || (p[2] != '\\' && p[2] != '/') {
		return false
	}
	c := p[0]
	return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')
}
