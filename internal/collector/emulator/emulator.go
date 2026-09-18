// Package emulator recolecta emuladores de Android, sus macros y las
// herramientas de macro instaladas. Es el colector que el consentimiento
// prometía desde la Fase 1 ("configuración de emuladores y macros de
// control") y que ninguna fase había implementado: la categoría EMULATOR
// existía en el reporte sin que nada la produjera.
//
// Recolecta SOLO metadatos: qué emulador está instalado, cuántos archivos de
// macro tiene y de cuándo son, y qué herramientas de automatización hay. No
// lee el contenido de ningún macro ni de ningún script.
package emulator

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/mirkovedia/mirkkkov-pc/internal/collector"
	"github.com/mirkovedia/mirkkkov-pc/internal/winfs/reghive"
	"github.com/mirkovedia/mirkkkov-pc/internal/winfs/wintext"
)

// Collector busca emuladores y herramientas de macro en disco y en las
// claves de desinstalación del hive SOFTWARE.
type Collector struct {
	// Root es la raíz del sistema ("C:\"). Todas las rutas conocidas se
	// resuelven relativas a ella, para poder testear sobre un directorio
	// temporal.
	Root string
	// SoftwareHive es una copia legible del hive SOFTWARE; vacío la omite.
	SoftwareHive string
}

// New crea el colector con la raíz C:\ y el hive SOFTWARE dado.
func New(softwareHive string) *Collector {
	return &Collector{Root: `C:\`, SoftwareHive: softwareHive}
}

func (c *Collector) Name() string  { return "emulator" }
func (c *Collector) Priority() int { return collector.PriorityRegistry }

// spec describe un producto conocido: dónde se instala, dónde guarda sus
// macros y cómo aparece en las claves de desinstalación.
type spec struct {
	Name string
	// Dirs son rutas relativas a Root cuya existencia delata la instalación.
	Dirs []string
	// UserDirs son rutas relativas al perfil de cada usuario.
	UserDirs []string
	// MacroDirs son directorios (relativos a Root) donde el producto guarda
	// macros o grabaciones de entrada.
	MacroDirs []string
	// UserMacroDirs son lo mismo, relativos al perfil de usuario.
	UserMacroDirs []string
	// Uninstall es el fragmento (en minúsculas) que matchea DisplayName.
	Uninstall string
	// Weight pondera las herramientas de macro: "info" para software de
	// periféricos que trae macros pero que cualquiera tiene (Logitech,
	// Razer); "" para herramientas cuyo único fin es automatizar entrada.
	Weight string
}

var emulators = []spec{
	{
		Name: "BlueStacks 5",
		Dirs: []string{`Program Files\BlueStacks_nxt`, `ProgramData\BlueStacks_nxt`},
		MacroDirs: []string{
			`ProgramData\BlueStacks_nxt\Engine\UserData\InputMapper\UserFiles`,
			`ProgramData\BlueStacks_nxt\Engine\UserData\Macros`,
		},
		Uninstall: "bluestacks",
	},
	{
		Name:      "BlueStacks 4",
		Dirs:      []string{`Program Files\BlueStacks`, `ProgramData\BlueStacks`},
		MacroDirs: []string{`ProgramData\BlueStacks\Engine\UserData\InputMapper\UserFiles`},
	},
	{
		Name:      "MSI App Player",
		Dirs:      []string{`Program Files\BlueStacks_msi5`, `ProgramData\BlueStacks_msi5`},
		MacroDirs: []string{`ProgramData\BlueStacks_msi5\Engine\UserData\InputMapper\UserFiles`},
		Uninstall: "msi app player",
	},
	{
		Name: "LDPlayer",
		Dirs: []string{`LDPlayer\LDPlayer9`, `LDPlayer\LDPlayer4`, `LDPlayer`, `Program Files\LDPlayer9`},
		MacroDirs: []string{
			`LDPlayer\LDPlayer9\vms\operationRecords`,
			`LDPlayer\LDPlayer9\vms\customizeConfigs`,
			`LDPlayer\LDPlayer4\vms\operationRecords`,
		},
		Uninstall: "ldplayer",
	},
	{
		Name:      "MEmu",
		Dirs:      []string{`Program Files\Microvirt\MEmu`, `Program Files (x86)\Microvirt\MEmu`},
		Uninstall: "memu",
	},
	{
		Name:          "NoxPlayer",
		Dirs:          []string{`Program Files (x86)\Nox`, `Program Files\Nox`, `Program Files (x86)\Bignox`},
		UserMacroDirs: []string{`AppData\Local\Nox\record`},
		Uninstall:     "nox",
	},
	{
		Name:      "GameLoop",
		Dirs:      []string{`Program Files\TxGameAssistant`, `Program Files (x86)\TxGameAssistant`, `Program Files\GameLoop`},
		Uninstall: "gameloop",
	},
	{
		Name:      "SmartGaGa",
		Dirs:      []string{`Program Files\SmartGaGa`, `Program Files (x86)\SmartGaGa`},
		Uninstall: "smartgaga",
	},
	{
		Name:      "Windows Subsystem for Android",
		UserDirs:  []string{`AppData\Local\Packages\MicrosoftCorporationII.WindowsSubsystemForAndroid_8wekyb3d8bbwe`},
		Uninstall: "windows subsystem for android",
	},
}

var macroTools = []spec{
	{
		Name:      "AutoHotkey",
		Dirs:      []string{`Program Files\AutoHotkey`, `Program Files (x86)\AutoHotkey`},
		UserDirs:  []string{`AppData\Local\Programs\AutoHotkey`},
		Uninstall: "autohotkey",
	},
	{Name: "AutoIt", Dirs: []string{`Program Files (x86)\AutoIt3`, `Program Files\AutoIt3`}, Uninstall: "autoit"},
	{Name: "TinyTask", Uninstall: "tinytask"},
	{Name: "Macro Recorder", Uninstall: "macro recorder"},
	{Name: "Pulover's Macro Creator", Uninstall: "macro creator"},
	{Name: "Mini Mouse Macro", Uninstall: "mini mouse macro"},
	{Name: "Auto Clicker", Uninstall: "auto clicker"},
	{Name: "Logitech G HUB", Dirs: []string{`Program Files\LGHUB`}, UserDirs: []string{`AppData\Local\LGHUB`}, Uninstall: "logitech g hub", Weight: "info"},
	{Name: "Razer Synapse", Dirs: []string{`Program Files (x86)\Razer\Synapse3`, `Program Files\Razer\Synapse3`}, Uninstall: "razer synapse", Weight: "info"},
	{Name: "Corsair iCUE", Dirs: []string{`Program Files\Corsair\CORSAIR iCUE 5 Software`, `Program Files (x86)\Corsair\CORSAIR iCUE 4 Software`}, Uninstall: "icue", Weight: "info"},
}

// userScriptDirs son carpetas del perfil donde un script .ahk suelto es una
// señal: un macro de Free Fire vive en el escritorio, no en un repositorio.
var userScriptDirs = []string{"Desktop", "Escritorio", "Documents", "Documentos", "Downloads", "Descargas"}

// Installed es un emulador o herramienta detectados.
type Installed struct {
	Name    string `json:"name"`
	Path    string `json:"path"`
	Via     string `json:"via"` // "dir" | "uninstall"
	Version string `json:"version,omitempty"`
	Weight  string `json:"weight,omitempty"`
}

// MacroStore es un directorio con macros o grabaciones de entrada.
type MacroStore struct {
	Emulator string    `json:"emulator"`
	Path     string    `json:"path"`
	Files    int       `json:"files"`
	Time     time.Time `json:"time"` // el archivo más reciente
	Sample   []string  `json:"sample,omitempty"`
}

// Script es un archivo de macro suelto en el perfil del usuario.
type Script struct {
	Path string    `json:"path"`
	Time time.Time `json:"time"`
	Size int64     `json:"size"`
}

func (c *Collector) Collect(ctx context.Context) ([]collector.Artifact, error) {
	var arts []collector.Artifact
	now := time.Now()
	emit := func(typ, source string, v any) {
		b, _ := json.Marshal(v)
		arts = append(arts, collector.Artifact{Type: typ, Source: source, Data: b, Collected: now})
	}

	users := c.userProfiles()
	uninstall := c.uninstallEntries()

	for _, e := range emulators {
		if err := ctx.Err(); err != nil {
			return arts, err
		}
		for _, inst := range c.detect(e, users, uninstall) {
			emit("emulator.installed", inst.Path, inst)
		}
		for _, dir := range c.macroDirs(e, users) {
			if store, ok := scanMacroDir(e.Name, dir); ok {
				emit("emulator.macro", store.Path, store)
			}
		}
	}
	for _, tool := range macroTools {
		for _, inst := range c.detect(tool, users, uninstall) {
			inst.Weight = tool.Weight
			emit("macro_tool", inst.Path, inst)
		}
	}
	for _, s := range c.userScripts(users) {
		emit("macro_script", s.Path, s)
	}
	return arts, nil
}

// detect reporta las instalaciones de un producto: por directorio y por
// clave de desinstalación. Un mismo producto puede aparecer por ambas vías;
// se emiten las dos porque son evidencia independiente.
func (c *Collector) detect(s spec, users []string, uninstall []uninstallEntry) []Installed {
	var out []Installed
	for _, rel := range s.Dirs {
		if p := filepath.Join(c.Root, rel); isDir(p) {
			out = append(out, Installed{Name: s.Name, Path: p, Via: "dir"})
		}
	}
	for _, u := range users {
		for _, rel := range s.UserDirs {
			if p := filepath.Join(u, rel); isDir(p) {
				out = append(out, Installed{Name: s.Name, Path: p, Via: "dir"})
			}
		}
	}
	if s.Uninstall != "" {
		for _, e := range uninstall {
			if strings.Contains(strings.ToLower(e.DisplayName), s.Uninstall) {
				out = append(out, Installed{Name: s.Name, Path: e.Location(), Via: "uninstall", Version: e.Version})
			}
		}
	}
	return out
}

func (c *Collector) macroDirs(s spec, users []string) []string {
	var out []string
	for _, rel := range s.MacroDirs {
		out = append(out, filepath.Join(c.Root, rel))
	}
	for _, u := range users {
		for _, rel := range s.UserMacroDirs {
			out = append(out, filepath.Join(u, rel))
		}
	}
	return out
}

// scanMacroDir cuenta los archivos de un directorio de macros. Solo nombres,
// tamaños y fechas: nunca se abre ninguno.
func scanMacroDir(emulator, dir string) (MacroStore, bool) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return MacroStore{}, false
	}
	store := MacroStore{Emulator: emulator, Path: dir}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		store.Files++
		if info.ModTime().After(store.Time) {
			store.Time = info.ModTime()
		}
		if len(store.Sample) < 5 {
			store.Sample = append(store.Sample, e.Name())
		}
	}
	if store.Files == 0 {
		return MacroStore{}, false
	}
	sort.Strings(store.Sample)
	return store, true
}

// userProfiles lista los perfiles reales bajo Users\ (sin Public, Default ni
// los de servicio).
func (c *Collector) userProfiles() []string {
	entries, err := os.ReadDir(filepath.Join(c.Root, "Users"))
	if err != nil {
		return nil
	}
	skip := map[string]bool{"public": true, "default": true, "default user": true, "all users": true, "defaultapppool": true}
	var out []string
	for _, e := range entries {
		if !e.IsDir() || skip[strings.ToLower(e.Name())] {
			continue
		}
		out = append(out, filepath.Join(c.Root, "Users", e.Name()))
	}
	return out
}

// userScripts busca scripts .ahk en el primer nivel de las carpetas visibles
// del perfil. No recorre subdirectorios: un proyecto con .ahk adentro no es
// lo que se busca, y la privacidad pesa más que la cobertura.
func (c *Collector) userScripts(users []string) []Script {
	var out []Script
	for _, u := range users {
		for _, d := range userScriptDirs {
			matches, _ := filepath.Glob(filepath.Join(u, d, "*.ahk"))
			for _, m := range matches {
				info, err := os.Stat(m)
				if err != nil {
					continue
				}
				out = append(out, Script{Path: m, Time: info.ModTime(), Size: info.Size()})
			}
		}
	}
	return out
}

func isDir(p string) bool {
	info, err := os.Stat(p)
	return err == nil && info.IsDir()
}

// uninstallEntry es una entrada de Programas y características.
type uninstallEntry struct {
	Key         string
	DisplayName string
	Version     string
	InstallDir  string
}

// Location devuelve la mejor ruta disponible: InstallLocation o, si falta,
// el nombre de la clave (que suele ser el nombre del producto o un GUID).
func (e uninstallEntry) Location() string {
	if e.InstallDir != "" {
		return e.InstallDir
	}
	return "HKLM\\...\\Uninstall\\" + e.Key
}

var uninstallKeys = []string{
	`Microsoft\Windows\CurrentVersion\Uninstall`,
	`WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall`,
}

// uninstallEntries lee las claves de desinstalación del hive SOFTWARE. Si el
// hive no está disponible devuelve nil y la detección sigue solo por disco.
func (c *Collector) uninstallEntries() []uninstallEntry {
	if c.SoftwareHive == "" {
		return nil
	}
	data, err := os.ReadFile(c.SoftwareHive)
	if err != nil {
		return nil
	}
	h, err := reghive.Open(data)
	if err != nil {
		return nil
	}
	return parseUninstall(h)
}

// parseUninstall recorre las dos vistas de Uninstall (64 y 32 bits).
func parseUninstall(h *reghive.Hive) []uninstallEntry {
	var out []uninstallEntry
	for _, path := range uninstallKeys {
		key, err := h.OpenKey(path)
		if err != nil {
			continue
		}
		subs, err := key.Subkeys()
		if err != nil {
			continue
		}
		for _, s := range subs {
			vals, err := s.Values()
			if err != nil {
				continue
			}
			e := uninstallEntry{Key: s.Name()}
			if v, ok := vals["DisplayName"]; ok {
				e.DisplayName = wintext.DecodeUTF16(v)
			}
			if e.DisplayName == "" {
				continue
			}
			if v, ok := vals["DisplayVersion"]; ok {
				e.Version = wintext.DecodeUTF16(v)
			}
			if v, ok := vals["InstallLocation"]; ok {
				e.InstallDir = strings.TrimSpace(wintext.DecodeUTF16(v))
			}
			out = append(out, e)
		}
	}
	return out
}
