package fsforensic

import (
	"path/filepath"
	"strings"
	"unicode"
)

// forensicExts son las extensiones de ejecutables/scripts que se retienen.
// .ahk (AutoHotkey) entra porque los macros de Free Fire se escriben en él.
var forensicExts = map[string]bool{
	".exe": true, ".dll": true, ".sys": true, ".bat": true, ".ps1": true,
	".cmd": true, ".vbs": true, ".scr": true, ".msi": true, ".ahk": true,
}

// hasExecutableToken reporta si alguno de los tokens del nombre es una
// extensión forense. Cubre tanto "esp.dll" como los nombres compuestos que
// llevan la extensión en el medio: "INJECTOR.EXE-1234.pf" (Prefetch) o
// "cheat.exe.bak". Un asset web como "esp-locale-ar-sa.js.gz" no lo tiene.
func hasExecutableToken(name string) bool {
	for _, tk := range tokenize(name) {
		if forensicExts["."+tk] {
			return true
		}
	}
	return false
}

// strongMarkers son marcadores largos e inequívocos: ninguna palabra legítima
// los contiene, así que se buscan como substring. Eso los hace robustos frente
// a nombres sin separadores ("aimbotloader.exe").
var strongMarkers = []string{"cheat", "aimbot", "ccleaner", "bleachbit"}

// weakMarkers son marcadores cortos o frecuentes como fragmento de palabras
// legítimas, así que solo cuentan como token completo. Buscarlos por substring
// producía falsos positivos masivos: "esp" matchea "response" y "namespace",
// "loader" matchea "uploader" y "downloader", "hook" matchea "pyproject-hooks".
// "injector" figura aparte de "inject" porque el matcheo es de token exacto.
var weakMarkers = []string{
	"inject", "injector", "loader", "bypass", "macro", "esp", "hook", "wipe",
}

// msPublicKeyToken es el token de clave pública de Microsoft presente en el
// nombre de todo componente del almacén WinSxS.
const msPublicKeyToken = "_31bf3856ad364e35_"

// winsxsPrefixes son los prefijos de arquitectura del almacén de componentes.
var winsxsPrefixes = []string{
	"amd64_microsoft-", "wow64_microsoft-", "x86_microsoft-", "msil_microsoft-",
}

// HasForensicExtension reporta si el nombre tiene una extensión de la whitelist.
func HasForensicExtension(name string) bool {
	return forensicExts[strings.ToLower(filepath.Ext(name))]
}

// IsSystemComponent reporta si el nombre corresponde a un componente del
// almacén WinSxS de Windows. Windows Update borra y reemplaza estos archivos de
// forma rutinaria, y sus nombres contienen palabras como "loader", "inject" o
// "hook" por motivos legítimos.
//
// Se identifica por el nombre y no por la ruta a propósito: la reconstrucción
// del directorio padre desde el MFT falla a menudo (rutas "<sin-resolver>"),
// así que una allowlist por ruta no los alcanzaría.
func IsSystemComponent(name string) bool {
	lower := strings.ToLower(name)
	if strings.Contains(lower, msPublicKeyToken) {
		return true
	}
	for _, p := range winsxsPrefixes {
		if strings.HasPrefix(lower, p) {
			return true
		}
	}
	return false
}

// IsSuspiciousName reporta si el nombre contiene un marcador sospechoso, de
// cualquiera de los dos niveles. Los componentes de sistema quedan excluidos.
func IsSuspiciousName(name string) bool {
	return HasStrongMarker(name) || hasWeakMarker(name)
}

// HasStrongMarker reporta si el nombre contiene un marcador inequívoco
// (substring). Los llamadores lo usan para distinguir el peso de la evidencia:
// un marcador fuerte justifica más severidad que uno débil.
func HasStrongMarker(name string) bool {
	if IsSystemComponent(name) {
		return false
	}
	lower := strings.ToLower(name)
	for _, m := range strongMarkers {
		if strings.Contains(lower, m) {
			return true
		}
	}
	return false
}

// vendorNamespaces son los primeros segmentos de los nombres con puntos que
// usan los ensamblados .NET y las bibliotecas de proveedores:
// "System.Runtime.Loader.dll", "Microsoft.Extensions.Hosting.dll". Cualquier
// aplicación .NET trae System.Runtime.Loader.dll; el primer escaneo real en
// un runner elevado lo marcó MEDIUM por el token "loader".
var vendorNamespaces = map[string]bool{
	"system": true, "microsoft": true, "windows": true, "netstandard": true,
	"mono": true, "xamarin": true, "newtonsoft": true, "unity": true,
	"unityengine": true, "google": true, "nvidia": true, "intel": true, "amd": true,
}

// hasWeakMarker reporta si el nombre del archivo lleva un marcador ambiguo en
// una posición que lo hace el sujeto del nombre. Es evidencia floja:
// "run-hook.cmd" y "esp.dll" matchean igual, y el primero es un script de
// desarrollo cualquiera. Por eso se le exige bastante:
//
//   - el nombre lleva una extensión ejecutable en alguno de sus tokens. Sin
//     eso, los assets web de Teams ("esp-coachmark-….js.gz") producían 174
//     hallazgos MEDIUM en una máquina limpia.
//   - el marcador es el primer o el último token del nombre, sin contar
//     extensiones, versiones ni hashes. "ff_loader_v2.exe" e "INJECTOR.EXE-
//     1A2B3C4D.pf" cuentan; "rust-analyzer-proc-macro-srv.exe", donde "macro"
//     es una palabra del medio de un nombre descriptivo, no.
//   - el nombre no es un ensamblado con espacio de nombres de proveedor
//     ("System.Runtime.Loader.dll").
//
// Solo mira el nombre del archivo, no los directorios: una carpeta llamada
// "loader" o "hook" es moneda corriente en cualquier árbol de código.
func hasWeakMarker(name string) bool {
	if IsSystemComponent(name) {
		return false
	}
	base := baseName(name)
	if !hasExecutableToken(base) {
		return false
	}
	stem := stemTokens(base)
	if len(stem) == 0 {
		return false
	}
	if len(stem) >= 3 && vendorNamespaces[stem[0]] && strings.Count(base, ".") >= 3 {
		return false
	}
	return isWeakMarker(stem[0]) || isWeakMarker(stem[len(stem)-1])
}

func isWeakMarker(token string) bool {
	for _, m := range weakMarkers {
		if token == m {
			return true
		}
	}
	return false
}

// baseName devuelve el último componente de una ruta de Windows o POSIX.
func baseName(path string) string {
	if i := strings.LastIndexAny(path, `\/`); i >= 0 {
		return path[i+1:]
	}
	return path
}

// stemTokens devuelve los tokens del nombre sin el ruido del final:
// extensiones ("exe", "pf"), versiones ("v2", "13") y hashes hexadecimales
// largos ("1a2b3c4d"). Lo que queda es el nombre propiamente dicho.
func stemTokens(base string) []string {
	tokens := tokenize(base)
	for len(tokens) > 0 && isTrailingNoise(tokens[len(tokens)-1]) {
		tokens = tokens[:len(tokens)-1]
	}
	return tokens
}

func isTrailingNoise(tk string) bool {
	if forensicExts["."+tk] || tk == "pf" {
		return true
	}
	digits, hexes := 0, 0
	for _, r := range tk {
		switch {
		case r >= '0' && r <= '9':
			digits++
			hexes++
		case r >= 'a' && r <= 'f':
			hexes++
		}
	}
	if digits == len(tk) { // "13", "2024"
		return true
	}
	if len(tk) >= 2 && tk[0] == 'v' && digits == len(tk)-1 { // "v2"
		return true
	}
	return len(tk) >= 8 && hexes == len(tk) // hash
}

// tokenize parte un nombre en tokens en minúscula, cortando por separadores
// (-, _, ., espacio) , por separadores de ruta (\, /, :) y por cambios de
// camelCase. Así "logUploaderSettings.ini" da [log uploader settings ini] y el
// marcador "loader" deja de matchear "Uploader".
//
// Corta por ruta porque los llamadores pasan el path completo del artefacto,
// no solo el nombre del archivo: sin eso "C:\...\Prefetch\INJECTOR.EXE" nunca
// produciría "injector" como token propio.
func tokenize(name string) []string {
	var tokens []string
	var cur []rune

	flush := func() {
		if len(cur) > 0 {
			tokens = append(tokens, strings.ToLower(string(cur)))
			cur = cur[:0]
		}
	}

	runes := []rune(name)
	for i, r := range runes {
		switch {
		case r == '-' || r == '_' || r == '.' || r == ' ' ||
			r == '\\' || r == '/' || r == ':':
			flush()
		case unicode.IsUpper(r) && i > 0 && unicode.IsLower(runes[i-1]):
			// Frontera camelCase: "logUploader" -> "log" + "Uploader".
			flush()
			cur = append(cur, r)
		default:
			cur = append(cur, r)
		}
	}
	flush()
	return tokens
}
