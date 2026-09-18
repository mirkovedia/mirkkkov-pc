package usn

import (
	"testing"
	"time"
)

func TestRecreated(t *testing.T) {
	now := time.Date(2026, 9, 17, 12, 0, 0, 0, time.UTC)
	install := now.Add(-400 * 24 * time.Hour)
	cases := []struct {
		name    string
		created time.Time
		want    bool
	}{
		{"journal de la instalación", install.Add(2 * time.Hour), false},
		{"recreado hace tres días", now.Add(-3 * 24 * time.Hour), true},
		{"recreado hace tres meses", now.Add(-90 * 24 * time.Hour), false},
		{"sin fecha de creación", time.Time{}, false},
	}
	for _, c := range cases {
		if got := Recreated(c.created, install, now); got != c.want {
			t.Errorf("%s: Recreated = %v, want %v", c.name, got, c.want)
		}
	}
	if Recreated(now.Add(-time.Hour), time.Time{}, now) {
		t.Error("sin fecha de instalación no se afirma nada")
	}
}
