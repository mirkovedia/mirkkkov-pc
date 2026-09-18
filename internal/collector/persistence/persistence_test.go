package persistence

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/mirkovedia/mirkkkov-pc/internal/collector"
	"github.com/mirkovedia/mirkkkov-pc/internal/winfs/authenticode"
	"github.com/mirkovedia/mirkkkov-pc/internal/winfs/reghive/reghivetest"
)

func utf16(s string) []byte {
	var b []byte
	for _, r := range s {
		b = append(b, byte(r), byte(r>>8))
	}
	return append(b, 0, 0)
}

func u32(v uint32) []byte {
	return []byte{byte(v), byte(v >> 8), byte(v >> 16), byte(v >> 24)}
}

// buildSoftwareHive arma un SOFTWARE con: Run (dos entradas), IFEO con un
// depurador sobre notepad.exe, AppInit_DLLs cargado y un Shell alterado.
func buildSoftwareHive(t *testing.T) string {
	t.Helper()
	b := reghivetest.NewBuilder()

	vDiscord := b.AddValue("Discord", utf16(`"C:\Users\x\AppData\Local\Discord\Update.exe" --processStart Discord.exe`), 1)
	vEvil := b.AddValue("Updater", utf16(`C:\Users\x\AppData\Roaming\svc\ffloader.exe /q`), 1)
	run := b.AddKey("Run", nil, []uint32{vDiscord, vEvil})
	runOnce := b.AddKey("RunOnce", nil, nil)
	cv := b.AddKey("CurrentVersion", []uint32{run, runOnce}, nil)
	win := b.AddKey("Windows", []uint32{cv}, nil)

	vDbg := b.AddValue("Debugger", utf16(`C:\Temp\hook.exe`), 1)
	notepad := b.AddKey("notepad.exe", nil, []uint32{vDbg})
	vVs := b.AddValue("Debugger", utf16(`"C:\Windows\system32\vsjitdebugger.exe" -p %ld -e %ld`), 1)
	vsjit := b.AddKey("AeDebug-ignore", nil, []uint32{vVs})
	ifeo := b.AddKey("Image File Execution Options", []uint32{notepad, vsjit}, nil)

	vAppInit := b.AddValue("AppInit_DLLs", utf16(`C:\Temp\inject.dll`), 1)
	vLoad := b.AddValue("LoadAppInit_DLLs", u32(1), 4)
	windowsKey := b.AddKey("Windows", nil, []uint32{vAppInit, vLoad})

	vShell := b.AddValue("Shell", utf16(`explorer.exe, C:\Temp\persist.exe`), 1)
	vUserinit := b.AddValue("Userinit", utf16(`C:\Windows\system32\userinit.exe,`), 1)
	winlogon := b.AddKey("Winlogon", nil, []uint32{vShell, vUserinit})

	ntcv := b.AddKey("CurrentVersion", []uint32{ifeo, windowsKey, winlogon}, nil)
	nt := b.AddKey("Windows NT", []uint32{ntcv}, nil)

	ms := b.AddKey("Microsoft", []uint32{win, nt}, nil)
	root := b.AddKey("ROOT", []uint32{ms}, nil)

	path := filepath.Join(t.TempDir(), "SOFTWARE")
	if err := os.WriteFile(path, b.Build(root), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func buildNTUser(t *testing.T, dir string) {
	t.Helper()
	b := reghivetest.NewBuilder()
	vSteam := b.AddValue("Steam", utf16(`"C:\Program Files (x86)\Steam\steam.exe" -silent`), 1)
	run := b.AddKey("Run", nil, []uint32{vSteam})
	cv := b.AddKey("CurrentVersion", []uint32{run}, nil)
	win := b.AddKey("Windows", []uint32{cv}, nil)
	ms := b.AddKey("Microsoft", []uint32{win}, nil)
	sw := b.AddKey("Software", []uint32{ms}, nil)
	root := b.AddKey("ROOT", []uint32{sw}, nil)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "NTUSER.DAT"), b.Build(root), 0o600); err != nil {
		t.Fatal(err)
	}
}

func byType(arts []collector.Artifact) map[string][]collector.Artifact {
	out := map[string][]collector.Artifact{}
	for _, a := range arts {
		out[a.Type] = append(out[a.Type], a)
	}
	return out
}

func newTestCollector(t *testing.T) (*Collector, string) {
	t.Helper()
	root := t.TempDir()
	c := &Collector{
		SoftwareHive: buildSoftwareHive(t),
		UsersDir:     filepath.Join(root, "Users"),
		ProgramData:  filepath.Join(root, "ProgramData"),
		ReadFile:     os.ReadFile,
		Verify: func(p string) authenticode.Result {
			if filepath.Base(p) == "ffloader.exe" {
				return authenticode.Result{Status: authenticode.StatusUnsigned}
			}
			return authenticode.Result{Status: authenticode.StatusSigned, Signer: "Vendor"}
		},
	}
	buildNTUser(t, filepath.Join(c.UsersDir, "jugador"))
	startup := filepath.Join(c.UsersDir, "jugador", `AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup`)
	os.MkdirAll(startup, 0o755)
	os.WriteFile(filepath.Join(startup, "macro.lnk"), []byte("x"), 0o644)
	os.WriteFile(filepath.Join(startup, "desktop.ini"), []byte("x"), 0o644)
	return c, root
}

func TestCollectorMetadata(t *testing.T) {
	c := New("")
	if c.Name() != "persistence" || c.Verify == nil || c.ReadFile == nil {
		t.Fatalf("New = %+v", c)
	}
	var _ collector.Collector = c
}

func TestAutorunsFromMachineAndUserHives(t *testing.T) {
	c, _ := newTestCollector(t)
	arts, err := c.Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	got := byType(arts)
	if len(got["autorun"]) != 3 {
		t.Fatalf("autorun = %d: %+v", len(got["autorun"]), got["autorun"])
	}
	var found bool
	for _, a := range got["autorun"] {
		var ar Autorun
		json.Unmarshal(a.Data, &ar)
		if ar.Name == "Updater" {
			found = true
			if ar.Path != `C:\Users\x\AppData\Roaming\svc\ffloader.exe` || ar.Signature.Status != authenticode.StatusUnsigned {
				t.Fatalf("Updater = %+v", ar)
			}
			if a.Source != ar.Path {
				t.Fatalf("Source debe ser la ruta resuelta, got %q", a.Source)
			}
		}
		if ar.Name == "Steam" && ar.Hive != "HKU:jugador" {
			t.Fatalf("Steam debe venir del NTUSER del perfil, got %+v", ar)
		}
	}
	if !found {
		t.Fatal("falta la entrada Updater")
	}
}

func TestIFEOAppInitAndWinlogon(t *testing.T) {
	c, _ := newTestCollector(t)
	arts, _ := c.Collect(context.Background())
	got := byType(arts)

	if len(got["ifeo_debugger"]) != 2 {
		t.Fatalf("ifeo = %d", len(got["ifeo_debugger"]))
	}
	if len(got["appinit_dll"]) != 1 {
		t.Fatalf("appinit = %d", len(got["appinit_dll"]))
	}
	var ai AppInitDLL
	json.Unmarshal(got["appinit_dll"][0].Data, &ai)
	if !ai.Enabled || ai.Value != `C:\Temp\inject.dll` {
		t.Fatalf("appinit = %+v", ai)
	}
	if len(got["winlogon_hijack"]) != 1 {
		t.Fatalf("winlogon = %d: Userinit de fábrica no debe reportarse", len(got["winlogon_hijack"]))
	}
	var w WinlogonValue
	json.Unmarshal(got["winlogon_hijack"][0].Data, &w)
	if w.Value != "Shell" {
		t.Fatalf("winlogon = %+v", w)
	}
}

func TestStartupFoldersSkipDesktopIni(t *testing.T) {
	c, _ := newTestCollector(t)
	arts, _ := c.Collect(context.Background())
	got := byType(arts)
	if len(got["startup_entry"]) != 1 {
		t.Fatalf("startup = %d: %+v", len(got["startup_entry"]), got["startup_entry"])
	}
}

func TestIsKnownDebugger(t *testing.T) {
	if !IsKnownDebugger(`"C:\Windows\system32\vsjitdebugger.exe" -p %ld`) {
		t.Fatal("vsjitdebugger es conocido")
	}
	if IsKnownDebugger(`C:\Temp\hook.exe`) {
		t.Fatal("hook.exe no es conocido")
	}
}

func TestMissingHivesAreNotFatal(t *testing.T) {
	c := &Collector{SoftwareHive: "no-existe", UsersDir: t.TempDir(), ProgramData: t.TempDir(), ReadFile: os.ReadFile}
	arts, err := c.Collect(context.Background())
	if err != nil || len(arts) != 0 {
		t.Fatalf("arts=%d err=%v", len(arts), err)
	}
}
