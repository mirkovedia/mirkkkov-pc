package emulator

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/mirkovedia/mirkkkov-pc/internal/collector"
	"github.com/mirkovedia/mirkkkov-pc/internal/winfs/reghive/reghivetest"
)

func utf16(s string) []byte {
	var b []byte
	for _, r := range s {
		b = append(b, byte(r), byte(r>>8))
	}
	return append(b, 0, 0)
}

func mkdirs(t *testing.T, root string, rels ...string) {
	t.Helper()
	for _, rel := range rels {
		if err := os.MkdirAll(filepath.Join(root, rel), 0o755); err != nil {
			t.Fatal(err)
		}
	}
}

func touch(t *testing.T, path string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("x"), 0o644); err != nil {
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

func TestCollectorMetadata(t *testing.T) {
	c := New("")
	if c.Name() != "emulator" || c.Root != `C:\` {
		t.Fatalf("New = %+v", c)
	}
	var _ collector.Collector = c
}

func TestCleanRootProducesNothing(t *testing.T) {
	c := &Collector{Root: t.TempDir()}
	arts, err := c.Collect(context.Background())
	if err != nil || len(arts) != 0 {
		t.Fatalf("arts=%d err=%v", len(arts), err)
	}
}

// TestDetectsBlueStacksWithMacros: BlueStacks instalado y con archivos en la
// carpeta de macros. Se reportan la instalación y el almacén de macros con
// cantidad, fecha y muestra de nombres; nunca el contenido.
func TestDetectsBlueStacksWithMacros(t *testing.T) {
	root := t.TempDir()
	mkdirs(t, root, `Program Files\BlueStacks_nxt`)
	touch(t, filepath.Join(root, `ProgramData\BlueStacks_nxt\Engine\UserData\InputMapper\UserFiles\FreeFire_headshot.json`))
	touch(t, filepath.Join(root, `ProgramData\BlueStacks_nxt\Engine\UserData\InputMapper\UserFiles\com.dts.freefireth.cfg`))

	arts, err := (&Collector{Root: root}).Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	got := byType(arts)
	if len(got["emulator.installed"]) != 2 { // Program Files y ProgramData
		t.Fatalf("installed = %d: %+v", len(got["emulator.installed"]), got["emulator.installed"])
	}
	if len(got["emulator.macro"]) != 1 {
		t.Fatalf("macro stores = %d", len(got["emulator.macro"]))
	}
	var store MacroStore
	if err := json.Unmarshal(got["emulator.macro"][0].Data, &store); err != nil {
		t.Fatal(err)
	}
	if store.Emulator != "BlueStacks 5" || store.Files != 2 || store.Time.IsZero() || len(store.Sample) != 2 {
		t.Fatalf("store = %+v", store)
	}
}

func TestDetectsNoxMacrosInUserProfile(t *testing.T) {
	root := t.TempDir()
	touch(t, filepath.Join(root, `Users\jugador\AppData\Local\Nox\record\auto_aim.record`))
	mkdirs(t, root, `Users\Public\AppData\Local\Nox\record`) // Public se ignora

	arts, _ := (&Collector{Root: root}).Collect(context.Background())
	got := byType(arts)
	if len(got["emulator.macro"]) != 1 {
		t.Fatalf("macro stores = %d", len(got["emulator.macro"]))
	}
}

func TestDetectsAutoHotkeyScriptsOnDesktop(t *testing.T) {
	root := t.TempDir()
	mkdirs(t, root, `Program Files\AutoHotkey`)
	touch(t, filepath.Join(root, `Users\jugador\Desktop\ff_macro.ahk`))
	touch(t, filepath.Join(root, `Users\jugador\Desktop\proyecto\lib\util.ahk`)) // no se recorre en profundidad

	arts, _ := (&Collector{Root: root}).Collect(context.Background())
	got := byType(arts)
	if len(got["macro_tool"]) != 1 {
		t.Fatalf("macro_tool = %d", len(got["macro_tool"]))
	}
	if len(got["macro_script"]) != 1 {
		t.Fatalf("macro_script = %d: %+v", len(got["macro_script"]), got["macro_script"])
	}
}

func TestPeripheralSoftwareIsWeightedInfo(t *testing.T) {
	root := t.TempDir()
	mkdirs(t, root, `Program Files\LGHUB`)
	arts, _ := (&Collector{Root: root}).Collect(context.Background())
	got := byType(arts)
	if len(got["macro_tool"]) != 1 {
		t.Fatalf("macro_tool = %d", len(got["macro_tool"]))
	}
	var inst Installed
	json.Unmarshal(got["macro_tool"][0].Data, &inst)
	if inst.Weight != "info" {
		t.Fatalf("Logitech G HUB debe pesar info, got %q", inst.Weight)
	}
}

// TestDetectsFromUninstallKeys: un LDPlayer instalado en una ruta rara igual
// aparece en Programas y características.
func TestDetectsFromUninstallKeys(t *testing.T) {
	b := reghivetest.NewBuilder()
	vName := b.AddValue("DisplayName", utf16("LDPlayer9"), 1)
	vVer := b.AddValue("DisplayVersion", utf16("9.0.66"), 1)
	vLoc := b.AddValue("InstallLocation", utf16(`D:\Juegos\LDPlayer9`), 1)
	ld := b.AddKey("LDPlayer9", nil, []uint32{vName, vVer, vLoc})
	vOther := b.AddValue("DisplayName", utf16("7-Zip"), 1)
	other := b.AddKey("7-Zip", nil, []uint32{vOther})
	uninstall := b.AddKey("Uninstall", []uint32{ld, other}, nil)
	cv := b.AddKey("CurrentVersion", []uint32{uninstall}, nil)
	win := b.AddKey("Windows", []uint32{cv}, nil)
	ms := b.AddKey("Microsoft", []uint32{win}, nil)
	root := b.AddKey("ROOT", []uint32{ms}, nil)

	hive := filepath.Join(t.TempDir(), "SOFTWARE")
	if err := os.WriteFile(hive, b.Build(root), 0o600); err != nil {
		t.Fatal(err)
	}
	arts, _ := (&Collector{Root: t.TempDir(), SoftwareHive: hive}).Collect(context.Background())
	got := byType(arts)
	if len(got["emulator.installed"]) != 1 {
		t.Fatalf("installed = %+v", got["emulator.installed"])
	}
	var inst Installed
	json.Unmarshal(got["emulator.installed"][0].Data, &inst)
	if inst.Name != "LDPlayer" || inst.Via != "uninstall" || inst.Version != "9.0.66" || inst.Path != `D:\Juegos\LDPlayer9` {
		t.Fatalf("inst = %+v", inst)
	}
}
