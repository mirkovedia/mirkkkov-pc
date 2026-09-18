// Package wincmd extrae la ruta del ejecutable de una línea de comando de
// Windows tal como aparece en el registro o en una tarea programada:
// con o sin comillas, con variables %VAR% y con argumentos detrás.
package wincmd

import (
	"os"
	"strings"
)

// ExePath devuelve la ruta absoluta del ejecutable de una línea de comando,
// o "" si no se puede determinar sin adivinar. Casos que resuelve:
//
//	"C:\Program Files\App\app.exe" --flag   → C:\Program Files\App\app.exe
//	C:\Tools\tool.exe /silent               → C:\Tools\tool.exe
//	%SystemRoot%\system32\svchost.exe -k x  → C:\Windows\system32\svchost.exe
//	rundll32.exe algo.dll,Entry             → "" (relativo a PATH: no se adivina)
func ExePath(command string) string {
	s := strings.TrimSpace(command)
	if s == "" {
		return ""
	}
	if strings.HasPrefix(s, `"`) {
		end := strings.Index(s[1:], `"`)
		if end < 0 {
			return ""
		}
		s = s[1 : 1+end]
	} else if i := strings.Index(strings.ToLower(s), ".exe"); i >= 0 {
		// Rutas sin comillas con espacios ("C:\Program Files\x\y.exe /a"):
		// la extensión marca dónde termina la ruta.
		s = s[:i+4]
	} else if fields := strings.Fields(s); len(fields) > 0 {
		s = fields[0]
	}
	s = ExpandEnv(s)
	if !isAbsolute(s) {
		return ""
	}
	return s
}

// ExpandEnv expande %VAR% con el entorno del proceso. Una variable que no
// existe se deja como está, para que la ruta resultante no parezca válida.
func ExpandEnv(s string) string {
	var out strings.Builder
	for {
		start := strings.IndexByte(s, '%')
		if start < 0 {
			break
		}
		end := strings.IndexByte(s[start+1:], '%')
		if end < 0 {
			break
		}
		name := s[start+1 : start+1+end]
		out.WriteString(s[:start])
		if v := os.Getenv(name); v != "" {
			out.WriteString(v)
		} else {
			out.WriteString("%" + name + "%")
		}
		s = s[start+1+end+1:]
	}
	out.WriteString(s)
	return out.String()
}

func isAbsolute(p string) bool {
	return len(p) >= 3 && p[1] == ':' && (p[2] == '\\' || p[2] == '/')
}
