//go:build windows

package ui

import (
	"context"
	"sync"
	"time"

	webview "github.com/jchv/go-webview2"
)

// shutdownGrace es cuánto se espera al escaneo tras cerrar la ventana antes
// de salir igual. Cubre de sobra el cierre del snapshot VSS; si el escaneo
// está trabado en una lectura de disco, el proceso no se queda colgado
// invisible para siempre.
const shutdownGrace = 20 * time.Second

// Run abre la ventana y bloquea hasta que el usuario la cierra.
//
// Debe llamarse desde el hilo principal con runtime.LockOSThread() activo:
// WebView2 exige que la interfaz viva siempre en el mismo hilo del sistema
// operativo, y Go puede mover una goroutine entre hilos en cualquier momento.
func Run(opts Options) error {
	w := webview.NewWithOptions(webview.WebViewOptions{
		Debug:     false,
		AutoFocus: true,
		WindowOptions: webview.WindowOptions{
			Title:  opts.Title,
			Width:  1100,
			Height: 780,
			Center: true,
		},
	})
	if w == nil {
		return ErrWebViewUnavailable
	}
	defer w.Destroy()

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

	w.SetHtml(Page())
	w.Run()

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
