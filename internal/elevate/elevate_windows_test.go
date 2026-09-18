//go:build windows

package elevate

import "testing"

func TestCommandLineQuotesArgumentsWithSpaces(t *testing.T) {
	got := commandLine([]string{"-console", "-out", `C:\Mis Reportes\r.json`})
	want := `-console -out "C:\Mis Reportes\r.json"`
	if got != want {
		t.Fatalf("commandLine = %q, want %q", got, want)
	}
}

func TestCommandLineLeavesPlainArgumentsAlone(t *testing.T) {
	if got := commandLine([]string{"-console", "-timeout", "10m"}); got != "-console -timeout 10m" {
		t.Fatalf("commandLine = %q", got)
	}
}

func TestCommandLineEmpty(t *testing.T) {
	if got := commandLine(nil); got != "" {
		t.Fatalf("commandLine(nil) = %q, want vacío", got)
	}
}
