package ui

import (
	"strings"
	"testing"
	"unicode"
)

// Regresiones de la revisión adversarial de la Fase 9.

// TestAssetsHaveNoInvisibleCharacters: la interfaz entera viaja embebida en
// el binario. Un carácter de control o un aislante bidi metido en el fuente
// (pasó una vez: un editor interpretó los U+0000 de una expresión regular y
// escribió los bytes) no se ve en ninguna revisión de código y cambia lo que
// el archivo hace.
func TestAssetsHaveNoInvisibleCharacters(t *testing.T) {
	for name, src := range map[string]string{"index.html": indexHTML, "app.css": appCSS, "app.js": appJS} {
		line := 1
		for _, r := range src {
			switch {
			case r == '\n':
				line++
			case r == '\t' || r == '\r':
			case unicode.IsControl(r), unicode.Is(unicode.Cf, r):
				t.Errorf("%s línea %d: carácter invisible U+%04X en el fuente", name, line, r)
			}
		}
	}
}

// TestCoverDoesNotShareClassWithRevealButton: .reveal es el botón de carpeta
// y fija width/height en 30px, que en Chromium también se aplican a un <rect>
// de SVG. La tapa del registro usaba esa misma clase, medía 30x30 y la
// animación de descubrir el papel nunca se vio.
func TestCoverDoesNotShareClassWithRevealButton(t *testing.T) {
	if strings.Contains(appJS, `"s-cover reveal"`) || strings.Contains(appCSS, ".s-cover.reveal") {
		t.Fatal("la tapa del registro no puede usar la clase reveal del botón de carpeta")
	}
	if !strings.Contains(appJS, `"s-cover uncover"`) || !strings.Contains(appCSS, ".s-cover.uncover") {
		t.Fatal("falta la clase uncover de la tapa del registro en JS o en CSS")
	}
}

// TestUntrustedTextGoesThroughVisible: los textos que controla quien es
// revisado pasan por visible(), que deja a la vista los caracteres bidi y de
// ancho cero en vez de obedecerlos.
func TestUntrustedTextGoesThroughVisible(t *testing.T) {
	for _, want := range []string{
		"function visible(", "function setPath(",
		"visible(f.title)", "setPath(pathEl, f.artifact",
		"visible(ev.title)", "visible(sig.signer)", "visible(rows[i][1])",
	} {
		if !strings.Contains(appJS, want) {
			t.Errorf("app.js debe contener %q", want)
		}
	}
	// Un nombre de clase no se arma con una cadena que venga de los datos.
	for _, bad := range []string{`sev.toLowerCase() + '"`, `"sig sig-" + sig.status`} {
		if strings.Contains(appJS, bad) {
			t.Errorf("app.js arma una clase con datos sin validar: %q", bad)
		}
	}
}

// TestPathsAreTruncatedFromTheStart: con unicode-bidi:plaintext la elipsis
// caía a la derecha y escondía el nombre del ejecutable, que es lo único que
// hay que ver.
func TestPathsAreTruncatedFromTheStart(t *testing.T) {
	if strings.Contains(appCSS, "unicode-bidi: plaintext;") {
		t.Fatal("unicode-bidi:plaintext devuelve el párrafo a ltr y recorta el nombre del archivo")
	}
	if !strings.Contains(appJS, `createElement("bdi")`) {
		t.Fatal("la ruta tiene que ir dentro de un <bdi dir=ltr>")
	}
}

// TestJSRevealableMatchesGo: el filtro del lado de la interfaz tiene que ser
// tan estricto como RevealablePath; ninguno acepta rutas UNC.
func TestJSRevealableMatchesGo(t *testing.T) {
	start := strings.Index(appJS, "function revealable(path)")
	if start < 0 {
		t.Fatal("falta revealable en app.js")
	}
	body := appJS[start : start+strings.Index(appJS[start:], "\n}")]
	if strings.Contains(body, "indexOf(") && strings.Contains(body, `=== 0`) {
		t.Fatalf("revealable no debe aceptar rutas por prefijo de red:\n%s", body)
	}
}

// TestExportIncludesEveryFinding: el documento exportado se arma clonando el
// DOM. Si se clona con los filtros puestos, sale incompleto sin avisar.
func TestExportIncludesEveryFinding(t *testing.T) {
	start := strings.Index(appJS, "function onExportClick()")
	if start < 0 {
		t.Fatal("falta onExportClick")
	}
	body := appJS[start:]
	resetFilters := strings.Index(body, `state.filters.text = "";`)
	clone := strings.Index(body, "cloneNode(true)")
	if resetFilters < 0 || clone < 0 || resetFilters > clone {
		t.Fatal("onExportClick debe limpiar los filtros ANTES de clonar el documento")
	}
	if !strings.Contains(body, `removeAttribute("width")`) {
		t.Fatal("el registro exportado no puede quedar con el ancho en píxeles de la ventana")
	}
}
