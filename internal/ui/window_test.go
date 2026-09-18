package ui

import "testing"

func TestFitWindow(t *testing.T) {
	cases := []struct {
		name                     string
		workW, workH             int
		w, h, wantMinW, wantMinH int
	}{
		{"FHD al 100 %: entra el tamaño de diseño", 1920, 1032, 1100, 780, 900, 600},
		{"notebook 1366x768 con barra de tareas", 1366, 720, 1100, 720, 900, 600},
		{"FHD al 150 %: 1280x720 lógicos", 1280, 672, 1100, 672, 900, 600},
		{"pantalla muy chica: el mínimo no puede superar la ventana", 800, 560, 800, 560, 800, 560},
		{"área de trabajo desconocida: tamaño de diseño", 0, 0, 1100, 780, 900, 600},
	}
	for _, c := range cases {
		w, h, minW, minH := fitWindow(c.workW, c.workH)
		if w != c.w || h != c.h || minW != c.wantMinW || minH != c.wantMinH {
			t.Errorf("%s: fitWindow(%d,%d) = %d,%d,%d,%d; want %d,%d,%d,%d",
				c.name, c.workW, c.workH, w, h, minW, minH, c.w, c.h, c.wantMinW, c.wantMinH)
		}
	}
}
