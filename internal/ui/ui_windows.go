//go:build windows

package ui

import (
	"context"
	"sync"
	"time"
	"unsafe"

	webview "github.com/jchv/go-webview2"
	"golang.org/x/sys/windows"
)

// shutdownGrace es cuánto se espera al escaneo tras cerrar la ventana antes
// de salir igual. Cubre de sobra el cierre del snapshot VSS; si el escaneo
// está trabado en una lectura de disco, el proceso no se queda colgado
// invisible para siempre.
const shutdownGrace = 20 * time.Second

// dispatchBeat es cada cuánto se despierta la cola de Dispatch. Ver Run.
const dispatchBeat = 250 * time.Millisecond

var (
	user32                   = windows.NewLazySystemDLL("user32.dll")
	procSystemParametersInfo = user32.NewProc("SystemParametersInfoW")
	procSetWindowPos         = user32.NewProc("SetWindowPos")
)

const (
	spiGetWorkArea = 0x0030
	swpNoSize      = 0x0001
	swpNoZOrder    = 0x0004
	swpNoActivate  = 0x0010
)

type winRect struct{ Left, Top, Right, Bottom int32 }

// workArea devuelve la pantalla primaria menos la barra de tareas, en las
// mismas coordenadas lógicas que usa CreateWindow (el proceso no declara ser
// consciente del DPI, así que Windows escala por él).
func workArea() (winRect, bool) {
	var r winRect
	ret, _, _ := procSystemParametersInfo.Call(spiGetWorkArea, 0, uintptr(unsafe.Pointer(&r)), 0)
	return r, ret != 0 && r.Right > r.Left && r.Bottom > r.Top
}

// Run abre la ventana y bloquea hasta que el usuario la cierra.
//
// Debe llamarse desde el hilo principal con runtime.LockOSThread() activo:
// WebView2 exige que la interfaz viva siempre en el mismo hilo del sistema
// operativo, y Go puede mover una goroutine entre hilos en cualquier momento.
func Run(opts Options) error {
	wa, haveArea := workArea()
	width, height, minW, minH := fitWindow(int(wa.Right-wa.Left), int(wa.Bottom-wa.Top))

	w := webview.NewWithOptions(webview.WebViewOptions{
		Debug:     false,
		AutoFocus: true,
		WindowOptions: webview.WindowOptions{
			Title:  opts.Title,
			Width:  uint(width),
			Height: uint(height),
			// El centrado de la librería usa la pantalla completa y aritmética
			// sin signo: con una ventana más alta que la pantalla daba una
			// posición negativa. Se centra a mano sobre el área de trabajo.
			Center: !haveArea,
		},
	})
	if w == nil {
		return ErrWebViewUnavailable
	}
	defer w.Destroy()

	if haveArea {
		x := int(wa.Left) + (int(wa.Right-wa.Left)-width)/2
		y := int(wa.Top) + (int(wa.Bottom-wa.Top)-height)/2
		procSetWindowPos.Call(uintptr(w.Window()), 0, uintptr(x), uintptr(y), 0, 0,
			swpNoSize|swpNoZOrder|swpNoActivate)
	}
	w.SetSize(minW, minH, webview.HintMin)

	// emit serializa el evento y lo empuja a JS en el hilo de UI. El escaneo
	// corre en una goroutine, así que toda llamada a Eval tiene que pasar por
	// Dispatch; saltearse esto produce cuelgues difíciles de diagnosticar.
	emit := func(e Event) {
		payload, err := e.JSON()
		if err != nil {
			return
		}
		w.Dispatch(func() {
			w.Eval("window.onAgentEvent(" + payload + ")")
		})
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	// scanDone se cierra cuando OnScan retorna. Si nunca se lanzó el escaneo
	// (el usuario rechazó el consentimiento) queda abierto y el cierre no
	// espera nada: ver el select de abajo.
	scanDone := make(chan struct{})
	var started bool
	var once sync.Once
	if err := w.Bind("startScan", func() {
		// once evita que un doble clic dispare dos escaneos concurrentes
		// sobre el mismo volumen.
		once.Do(func() {
			started = true
			go func() {
				defer close(scanDone)
				if opts.OnScan != nil {
					opts.OnScan(ctx, emit)
				}
			}()
		})
	}); err != nil {
		return err
	}
	if err := w.Bind("cancelScan", func() {
		cancel()
	}); err != nil {
		return err
	}
	if err := w.Bind("closeApp", func() {
		w.Terminate()
	}); err != nil {
		return err
	}
	// revealPath abre el explorador en la ubicación del artefacto. Es lo que
	// permite pasar del hallazgo al archivo sin copiar rutas a mano.
	if err := w.Bind("revealPath", func(path string) bool {
		return Reveal(path) == nil
	}); err != nil {
		return err
	}
	// exportHTML recibe la pantalla de resultados ya renderizada y la escribe
	// junto al reporte. Devuelve la ruta o "" si falló.
	if err := w.Bind("exportHTML", func(html string) string {
		if opts.ExportHTML == nil {
			return ""
		}
		path, err := opts.ExportHTML(html)
		if err != nil {
			return ""
		}
		return path
	}); err != nil {
		return err
	}

	// Latido de la cola de Dispatch.
	//
	// Dispatch encola la función y avisa al hilo de UI con PostThreadMessage.
	// Los mensajes de hilo se PIERDEN mientras el hilo está en un bucle modal
	// (arrastrar o redimensionar la ventana, el menú de sistema): el bucle
	// interno de Windows los retira y los descarta. Si el escaneo terminaba
	// justo mientras alguien movía la ventana, el evento scan_done quedaba
	// encolado para siempre y la pantalla seguía en "Revisando" con el
	// reporte ya escrito. Un Dispatch vacío periódico vuelve a despertar la
	// cola, que se drena entera cada vez.
	stopBeat := make(chan struct{})
	go func() {
		t := time.NewTicker(dispatchBeat)
		defer t.Stop()
		for {
			select {
			case <-stopBeat:
				return
			case <-t.C:
				w.Dispatch(func() {})
			}
		}
	}()

	w.SetHtml(Page())
	w.Run()
	close(stopBeat)

	// La ventana se cerró. Cancelar el escaneo y esperar a que suelte lo que
	// tomó: sin esta espera, el proceso moría con el snapshot VSS abierto.
	cancel()
	if started {
		select {
		case <-scanDone:
		case <-time.After(shutdownGrace):
		}
	}
	return nil
}
