// Package authenticode verifica la firma digital de ejecutables y drivers
// con las APIs de Windows (WinVerifyTrust y los catálogos de CryptCAT),
// invocadas por syscall: cero CGO, cero dependencias.
//
// Es lo que reemplaza la heurística "driver fuera de la ruta estándar": un
// binario firmado por un editor válido es lo normal en cualquier máquina; un
// driver de kernel sin firma en un Windows moderno es una anomalía que vale
// la pena mirar. El spec de Fase 5 descartó esto por creer que requería
// criptografía propia; en realidad Windows ya la trae, solo hay que llamarla.
package authenticode

import (
	"strings"
	"sync"
)

// Status es el resultado de la verificación.
type Status string

const (
	// StatusSigned indica firma válida, embebida en el archivo o en un
	// catálogo del sistema.
	StatusSigned Status = "signed"
	// StatusUnsigned indica que el archivo no tiene firma en ningún lado.
	StatusUnsigned Status = "unsigned"
	// StatusInvalid indica que hay firma pero no verifica: hash alterado,
	// raíz no confiable, certificado revocado o explícitamente desconfiado.
	StatusInvalid Status = "invalid"
	// StatusUnknown indica que no se pudo determinar: el archivo no existe,
	// no se pudo abrir o la API falló. NUNCA se interpreta como evidencia.
	StatusUnknown Status = "unknown"
)

// Result es lo que se adjunta al artefacto.
type Result struct {
	Status Status `json:"status"`
	// Signer es el nombre del firmante (CN del certificado hoja). Solo se
	// resuelve para firmas embebidas; en catálogo el firmante es Microsoft.
	Signer string `json:"signer,omitempty"`
	// Catalog es true cuando la firma vino de un catálogo del sistema.
	Catalog bool `json:"catalog,omitempty"`
	// Detail explica un unknown o un invalid en términos de la API.
	Detail string `json:"detail,omitempty"`
}

// Verifier es la firma de la función de verificación, para que los
// colectores puedan inyectar una falsa en tests.
type Verifier func(path string) Result

// cache memoriza por ruta dentro del proceso. Un escaneo consulta la misma
// imagen muchas veces (svchost.exe aparece decenas de veces en la lista de
// procesos) y cada verificación de catálogo cuesta decenas de milisegundos.
var cache sync.Map

// Verify verifica la firma del archivo en path. Nunca falla: cualquier
// problema termina en StatusUnknown con el detalle.
func Verify(path string) Result {
	key := strings.ToLower(strings.TrimSpace(path))
	if key == "" {
		return Result{Status: StatusUnknown, Detail: "ruta vacía"}
	}
	if v, ok := cache.Load(key); ok {
		return v.(Result)
	}
	if isPackagedApp(key) {
		// No se cachea: es una decisión por ruta, más barata que el mapa.
		return Result{Status: StatusUnknown, Detail: "aplicación empaquetada (MSIX): la firma es del paquete, no del binario"}
	}
	r := verifyFile(path)
	cache.Store(key, r)
	return r
}

// isPackagedApp reporta si la ruta (en minúsculas) cae dentro de WindowsApps.
//
// Las apps de la Store (WhatsApp, Widgets, el propio Bloc de notas nuevo) se
// firman a nivel de paquete: AppxSignature.p7x cubre el bloque entero y los
// .exe de adentro no llevan firma embebida ni figuran en los catálogos del
// sistema. WinVerifyTrust los ve "sin firma" y sería una acusación falsa: la
// carpeta pertenece a TrustedInstaller y nadie escribe ahí sin que Windows
// haya validado el paquete. La primera calibración real de Fase 8 marcó
// WhatsApp y WidgetService por esto.
func isPackagedApp(lowerPath string) bool {
	return strings.Contains(lowerPath, `\program files\windowsapps\`)
}

// ResetCache vacía la caché. Solo para tests.
func ResetCache() { cache = sync.Map{} }

// IsTrusted reporta si el resultado representa una firma válida.
func (r Result) IsTrusted() bool { return r.Status == StatusSigned }
