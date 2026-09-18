// Package persistence recolecta los mecanismos de arranque automático que el
// colector de servicios y tareas no cubre: claves Run/RunOnce (de máquina y
// de cada usuario), carpetas de inicio, depuradores IFEO, AppInit_DLLs y
// los valores Shell/Userinit de Winlogon.
//
// Un cheat que sobrevive al reinicio tiene que engancharse en alguno de
// estos lugares. Las entradas comunes (Discord, Steam, OneDrive) son
// evidencia neutra: se resumen. Lo que escala es un ejecutable sin firma en
// AppData o Temp, un depurador colgado de un proceso, o un Shell que no es
// explorer.exe.
package persistence

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/mirkovedia/mirkkkov-pc/internal/collector"
	"github.com/mirkovedia/mirkkkov-pc/internal/winfs/authenticode"
	"github.com/mirkovedia/mirkkkov-pc/internal/winfs/lockedfile"
	"github.com/mirkovedia/mirkkkov-pc/internal/winfs/reghive"
	"github.com/mirkovedia/mirkkkov-pc/internal/winfs/wincmd"
	"github.com/mirkovedia/mirkkkov-pc/internal/winfs/wintext"
)

// Collector lee el hive SOFTWARE, el NTUSER.DAT de cada perfil y las
// carpetas de inicio.
type Collector struct {
	SoftwareHive string
	UsersDir     string // C:\Users
	ProgramData  string // C:\ProgramData
	Verify       authenticode.Verifier
	// ReadFile lee un hive. Por defecto lockedfile.ReadFile, porque el
	// NTUSER.DAT del usuario con sesión iniciada está tomado en exclusiva.
	ReadFile func(string) ([]byte, error)
}

// New crea el colector con las rutas reales del sistema.
func New(softwareHive string) *Collector {
	return &Collector{
		SoftwareHive: softwareHive,
		UsersDir:     `C:\Users`,
		ProgramData:  `C:\ProgramData`,
		Verify:       authenticode.Verify,
		ReadFile:     lockedfile.ReadFile,
	}
}

func (c *Collector) Name() string  { return "persistence" }
func (c *Collector) Priority() int { return collector.PriorityRegistry }

// Autorun es una entrada de Run/RunOnce.
type Autorun struct {
	Hive      string              `json:"hive"` // "HKLM" o "HKU:<perfil>"
	Key       string              `json:"key"`  // "Run" | "RunOnce" | "Run (WOW64)"
	Name      string              `json:"name"`
	Command   string              `json:"command"`
	Path      string              `json:"path,omitempty"` // ejecutable resuelto
	Signature authenticode.Result `json:"Signature"`
}

// StartupEntry es un archivo en una carpeta de inicio.
type StartupEntry struct {
	Profile string    `json:"profile"` // "common" o el nombre del perfil
	Path    string    `json:"path"`
	Time    time.Time `json:"time"`
}

// IFEODebugger es un depurador colgado de un ejecutable: cada vez que
// Windows lanza Image, ejecuta Debugger en su lugar.
type IFEODebugger struct {
	Image    string `json:"image"`
	Debugger string `json:"debugger"`
}

// AppInitDLL es el valor AppInit_DLLs, que se inyecta en todo proceso que
// cargue user32.dll.
type AppInitDLL struct {
	Value   string `json:"value"`
	Enabled bool   `json:"enabled"`
	Wow64   bool   `json:"wow64"`
}

// WinlogonValue es un valor de Winlogon que no es el estándar.
type WinlogonValue struct {
	Value    string `json:"value"` // "Shell" | "Userinit"
	Data     string `json:"data"`
	Expected string `json:"expected"`
}

var hklmRunKeys = []struct{ path, label string }{
	{`Microsoft\Windows\CurrentVersion\Run`, "Run"},
	{`Microsoft\Windows\CurrentVersion\RunOnce`, "RunOnce"},
	{`WOW6432Node\Microsoft\Windows\CurrentVersion\Run`, "Run (WOW64)"},
	{`WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce`, "RunOnce (WOW64)"},
}

var hkuRunKeys = []struct{ path, label string }{
	{`Software\Microsoft\Windows\CurrentVersion\Run`, "Run"},
	{`Software\Microsoft\Windows\CurrentVersion\RunOnce`, "RunOnce"},
}

func (c *Collector) Collect(ctx context.Context) ([]collector.Artifact, error) {
	var arts []collector.Artifact
	now := time.Now()
	emit := func(typ, source string, v any) {
		b, _ := json.Marshal(v)
		arts = append(arts, collector.Artifact{Type: typ, Source: source, Data: b, Collected: now})
	}

	if h := c.openHive(c.SoftwareHive); h != nil {
		for _, k := range hklmRunKeys {
			for _, a := range c.readRunKey(h, k.path, "HKLM", k.label) {
				emit("autorun", a.source(), a)
			}
		}
		for _, d := range readIFEO(h) {
			emit("ifeo_debugger", d.Image, d)
		}
		for _, a := range readAppInit(h) {
			emit("appinit_dll", a.Value, a)
		}
		for _, w := range readWinlogon(h) {
			emit("winlogon_hijack", w.Data, w)
		}
	}

	for _, profile := range c.profiles() {
		if err := ctx.Err(); err != nil {
			return arts, err
		}
		name := filepath.Base(profile)
		if h := c.openHive(filepath.Join(profile, "NTUSER.DAT")); h != nil {
			for _, k := range hkuRunKeys {
				for _, a := range c.readRunKey(h, k.path, "HKU:"+name, k.label) {
					emit("autorun", a.source(), a)
				}
			}
		}
		startup := filepath.Join(profile, `AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup`)
		for _, e := range readStartup(name, startup) {
			emit("startup_entry", e.Path, e)
		}
	}
	common := filepath.Join(c.ProgramData, `Microsoft\Windows\Start Menu\Programs\StartUp`)
	for _, e := range readStartup("common", common) {
		emit("startup_entry", e.Path, e)
	}
	return arts, nil
}

func (a Autorun) source() string {
	if a.Path != "" {
		return a.Path
	}
	return a.Command
}

func (c *Collector) openHive(path string) *reghive.Hive {
	if path == "" {
		return nil
	}
	read := c.ReadFile
	if read == nil {
		read = os.ReadFile
	}
	data, err := read(path)
	if err != nil {
		return nil
	}
	h, err := reghive.Open(data)
	if err != nil {
		return nil
	}
	return h
}

// readRunKey lee todos los valores de una clave Run y verifica la firma de
// cada ejecutable.
func (c *Collector) readRunKey(h *reghive.Hive, keyPath, hive, label string) []Autorun {
	key, err := h.OpenKey(keyPath)
	if err != nil {
		return nil
	}
	vals, err := key.Values()
	if err != nil {
		return nil
	}
	var out []Autorun
	for name, raw := range vals {
		cmd := strings.TrimSpace(wintext.DecodeUTF16(raw))
		if cmd == "" {
			continue
		}
		a := Autorun{Hive: hive, Key: label, Name: name, Command: cmd, Path: wincmd.ExePath(cmd)}
		a.Signature = authenticode.Result{Status: authenticode.StatusUnknown}
		if a.Path != "" && c.Verify != nil {
			a.Signature = c.Verify(a.Path)
		}
		out = append(out, a)
	}
	return out
}

// knownDebuggers son depuradores IFEO que instalan herramientas legítimas.
var knownDebuggers = []string{"vsjitdebugger", "procdump", "gflags", "windbg"}

// readIFEO recorre Image File Execution Options buscando valores Debugger.
func readIFEO(h *reghive.Hive) []IFEODebugger {
	key, err := h.OpenKey(`Microsoft\Windows NT\CurrentVersion\Image File Execution Options`)
	if err != nil {
		return nil
	}
	subs, err := key.Subkeys()
	if err != nil {
		return nil
	}
	var out []IFEODebugger
	for _, s := range subs {
		raw, _, err := s.Value("Debugger")
		if err != nil {
			continue
		}
		dbg := strings.TrimSpace(wintext.DecodeUTF16(raw))
		if dbg == "" {
			continue
		}
		out = append(out, IFEODebugger{Image: s.Name(), Debugger: dbg})
	}
	return out
}

// IsKnownDebugger reporta si el depurador es de una herramienta conocida.
// Lo usa el motor de severidad para no escalar el JIT de Visual Studio.
func IsKnownDebugger(debugger string) bool {
	lower := strings.ToLower(debugger)
	for _, k := range knownDebuggers {
		if strings.Contains(lower, k) {
			return true
		}
	}
	return false
}

func readAppInit(h *reghive.Hive) []AppInitDLL {
	var out []AppInitDLL
	for _, view := range []struct {
		path  string
		wow64 bool
	}{
		{`Microsoft\Windows NT\CurrentVersion\Windows`, false},
		{`WOW6432Node\Microsoft\Windows NT\CurrentVersion\Windows`, true},
	} {
		key, err := h.OpenKey(view.path)
		if err != nil {
			continue
		}
		raw, _, err := key.Value("AppInit_DLLs")
		if err != nil {
			continue
		}
		value := strings.TrimSpace(wintext.DecodeUTF16(raw))
		if value == "" {
			continue
		}
		enabled := false
		if load, _, err := key.Value("LoadAppInit_DLLs"); err == nil && len(load) >= 4 {
			enabled = binary.LittleEndian.Uint32(load[:4]) != 0
		}
		out = append(out, AppInitDLL{Value: value, Enabled: enabled, Wow64: view.wow64})
	}
	return out
}

// readWinlogon compara Shell y Userinit con sus valores de fábrica.
func readWinlogon(h *reghive.Hive) []WinlogonValue {
	key, err := h.OpenKey(`Microsoft\Windows NT\CurrentVersion\Winlogon`)
	if err != nil {
		return nil
	}
	var out []WinlogonValue
	if raw, _, err := key.Value("Shell"); err == nil {
		shell := strings.TrimSpace(wintext.DecodeUTF16(raw))
		if shell != "" && !strings.EqualFold(shell, "explorer.exe") {
			out = append(out, WinlogonValue{Value: "Shell", Data: shell, Expected: "explorer.exe"})
		}
	}
	if raw, _, err := key.Value("Userinit"); err == nil {
		userinit := strings.TrimSpace(wintext.DecodeUTF16(raw))
		if userinit != "" && !isStandardUserinit(userinit) {
			out = append(out, WinlogonValue{Value: "Userinit", Data: userinit, Expected: `C:\Windows\system32\userinit.exe,`})
		}
	}
	return out
}

// isStandardUserinit acepta el valor de fábrica con o sin la coma final y
// con el SystemRoot literal o como variable.
func isStandardUserinit(v string) bool {
	lower := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(v), ","))
	return lower == `c:\windows\system32\userinit.exe` || lower == `%systemroot%\system32\userinit.exe`
}

func readStartup(profile, dir string) []StartupEntry {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var out []StartupEntry
	for _, e := range entries {
		if e.IsDir() || strings.EqualFold(e.Name(), "desktop.ini") {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		out = append(out, StartupEntry{Profile: profile, Path: filepath.Join(dir, e.Name()), Time: info.ModTime()})
	}
	return out
}

func (c *Collector) profiles() []string {
	entries, err := os.ReadDir(c.UsersDir)
	if err != nil {
		return nil
	}
	skip := map[string]bool{"public": true, "default": true, "default user": true, "all users": true}
	var out []string
	for _, e := range entries {
		if !e.IsDir() || skip[strings.ToLower(e.Name())] {
			continue
		}
		out = append(out, filepath.Join(c.UsersDir, e.Name()))
	}
	return out
}
