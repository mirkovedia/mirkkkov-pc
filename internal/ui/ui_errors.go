package ui

import (
	"context"
	"errors"
)

// ErrWebViewUnavailable indica que no se pudo crear la ventana, casi siempre
// porque falta el runtime de WebView2. El llamador debe degradar a consola con
// un mensaje claro: un escaneo que no arranca es peor que uno feo.
var ErrWebViewUnavailable = errors.New("no se pudo iniciar WebView2")

// Options configura la ventana.
type Options struct {
	Title string
	// OnScan se ejecuta en una goroutine cuando el usuario acepta el
	// consentimiento. emit ya viene envuelta en Dispatch, así que es seguro
	// llamarla desde cualquier goroutine.
	//
	// ctx se cancela cuando el usuario pulsa "Cancelar" o cierra la ventana.
	// El escaneo tiene que respetarlo: la ventana espera a que OnScan
	// retorne antes de terminar el proceso, para que los recursos que el
	// escaneo tomó (el snapshot VSS, sobre todo) se liberen. Un snapshot
	// huérfano ocupa espacio en el disco del jugador hasta que alguien lo
	// borra a mano.
	OnScan func(ctx context.Context, emit func(Event))
	// ExportHTML, si no es nil, recibe el HTML de la pantalla de resultados
	// cuando el usuario pide exportarla. Devuelve la ruta escrita.
	ExportHTML func(html string) (string, error)
}
