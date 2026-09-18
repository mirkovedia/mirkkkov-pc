package wincmd

import "testing"

func TestExePath(t *testing.T) {
	t.Setenv("SystemRoot", `C:\Windows`)
	cases := map[string]string{
		`"C:\Program Files (x86)\Google\GoogleUpdater\updater.exe" --wake`: `C:\Program Files (x86)\Google\GoogleUpdater\updater.exe`,
		`C:\Program Files\App\app.exe /silent`:                             `C:\Program Files\App\app.exe`,
		`C:\Tools\tool.exe`:                                                `C:\Tools\tool.exe`,
		`%SystemRoot%\system32\svchost.exe -k netsvcs`:                     `C:\Windows\system32\svchost.exe`,
		`"%SystemRoot%\explorer.exe"`:                                      `C:\Windows\explorer.exe`,
		`rundll32.exe algo.dll,Entry`:                                      "",
		`cmd.exe`:                                                          "",
		`%NOEXISTE%\x.exe`:                                                 "",
		`"sin cierre`:                                                      "",
		``:                                                                 "",
	}
	for in, want := range cases {
		if got := ExePath(in); got != want {
			t.Errorf("ExePath(%q) = %q, want %q", in, got, want)
		}
	}
}
