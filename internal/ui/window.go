package ui

// Tamaño de diseño de la ventana y el mínimo al que se la puede achicar.
const (
	designWidth  = 1100
	designHeight = 780
	minWidth     = 900
	minHeight    = 600
)

// fitWindow devuelve el tamaño de la ventana para un área de trabajo dada
// (la pantalla menos la barra de tareas) y el mínimo que se le puede fijar.
//
// La ventana medía 1100x780 fijos. En una notebook de 1366x768, o en una
// FHD con la escala al 150 % (1280x720 lógicos para un proceso que no es
// consciente del DPI), no entra: el pie con el avance y el botón Cancelar
// quedaba detrás de la barra de tareas, y en el segundo caso la barra de
// título quedaba fuera de la pantalla y la ventana no se podía mover.
func fitWindow(workW, workH int) (w, h, minW, minH int) {
	w, h = designWidth, designHeight
	if workW > 0 && w > workW {
		w = workW
	}
	if workH > 0 && h > workH {
		h = workH
	}
	minW, minH = minWidth, minHeight
	if minW > w {
		minW = w
	}
	if minH > h {
		minH = h
	}
	return w, h, minW, minH
}
