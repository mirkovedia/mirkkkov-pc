// internal/verdict/review_fixes_test.go
//
// Defectos que encontró la revisión adversarial de la Fase 9. Los dos
// existían desde mucho antes del rediseño; los hizo visibles dibujar la
// actividad en el tiempo.
package verdict

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/mirkovedia/mirkkkov-pc/internal/collector"
	"github.com/mirkovedia/mirkkkov-pc/internal/collector/amcache"
	"github.com/mirkovedia/mirkkkov-pc/internal/collector/bam"
	"github.com/mirkovedia/mirkkkov-pc/internal/collector/shimcache"
	"github.com/mirkovedia/mirkkkov-pc/internal/report"
)

// hiveArtifact arma el artefacto EXACTAMENTE como lo hace el colector real:
// el struct real serializado, con Source = ruta del hive. Es lo que faltaba:
// los tests anteriores ponían el ejecutable en Source, cosa que ninguno de
// estos tres colectores hace.
func hiveArtifact(t *testing.T, artType string, entry any) collector.Artifact {
	t.Helper()
	data, err := json.Marshal(entry)
	if err != nil {
		t.Fatal(err)
	}
	return collector.Artifact{Type: artType, Source: `C:\Users\x\AppData\Local\Temp\mirkkkov-1\SYSTEM`, Data: data}
}

// TestHiveBackedSourcesEscalateByExecutableName: un aimbot.exe ejecutado y
// borrado queda en BAM, ShimCache y AmCache, que son justamente las fuentes
// que sobreviven al borrado. Las tres tenían Source = hive, así que ninguna
// escalaba y el veredicto salía LIMPIO.
func TestHiveBackedSourcesEscalateByExecutableName(t *testing.T) {
	now := time.Now()
	cases := []struct {
		name string
		art  collector.Artifact
		want string
	}{
		{"bam", hiveArtifact(t, "bam", bam.Entry{SID: "S-1-5-21-1", ExecutablePath: `\Device\HarddiskVolume3\Users\x\Desktop\aimbot.exe`, LastExecution: now}),
			`\Device\HarddiskVolume3\Users\x\Desktop\aimbot.exe`},
		{"shimcache", hiveArtifact(t, "shimcache", shimcache.Entry{Path: `C:\Users\x\Desktop\aimbot.exe`, ModifiedTime: now}),
			`C:\Users\x\Desktop\aimbot.exe`},
		{"amcache", hiveArtifact(t, "amcache", amcache.Entry{SHA1: strings.Repeat("0", 40), Path: `c:\users\x\desktop\aimbot.exe`}),
			`c:\users\x\desktop\aimbot.exe`},
	}
	for _, c := range cases {
		if got := artifactOf(c.art); got != c.want {
			t.Errorf("%s: artifactOf = %q, want %q", c.name, got, c.want)
		}
		if r := escalate(c.art, ruleFor(c.art.Type)); r.Severity != SevMedium {
			t.Errorf("%s: Severity = %s, want MEDIUM (neutro + marcador fuerte)", c.name, r.Severity)
		}
		p := Preview(c.art)
		if !p.Notable || p.Artifact != c.want {
			t.Errorf("%s: la vista en vivo debe mostrarlo con su ejecutable, got %+v", c.name, p)
		}
	}

	results := []collector.Result{
		{Collector: "bam", Artifacts: []collector.Artifact{cases[0].art}},
		{Collector: "shimcache", Artifacts: []collector.Artifact{cases[1].art}},
	}
	findings, v := Evaluate(results)
	if v.Level != report.LevelSospechoso {
		t.Fatalf("dos fuentes independientes registran aimbot.exe: Level = %s, want SOSPECHOSO", v.Level)
	}
	for _, f := range findings {
		if f.Severity == SevMedium && strings.Contains(f.Artifact, "SYSTEM") {
			t.Errorf("el hallazgo debe apuntar al ejecutable, no al hive: %q", f.Artifact)
		}
	}
}

// TestHiveBackedEntriesAreNotCollapsedIntoOne: todas las entradas de un hive
// comparten Source. Deduplicando por Source, el segundo ejecutable sospechoso
// desaparecía detrás del primero.
func TestHiveBackedEntriesAreNotCollapsedIntoOne(t *testing.T) {
	results := []collector.Result{{Collector: "shimcache", Artifacts: []collector.Artifact{
		hiveArtifact(t, "shimcache", shimcache.Entry{Path: `C:\Users\x\Desktop\aimbot.exe`}),
		hiveArtifact(t, "shimcache", shimcache.Entry{Path: `C:\Users\x\Downloads\cheat_panel.exe`}),
		hiveArtifact(t, "shimcache", shimcache.Entry{Path: `C:\Windows\System32\notepad.exe`}),
	}}}
	findings, _ := Evaluate(results)
	flagged := 0
	for _, f := range findings {
		if f.Severity == SevMedium {
			flagged++
		}
	}
	if flagged != 2 {
		t.Fatalf("hallazgos destacados = %d, want 2 (uno por ejecutable)", flagged)
	}
}

func TestHiveBackedNormalEntriesStayNeutral(t *testing.T) {
	a := hiveArtifact(t, "bam", bam.Entry{ExecutablePath: `\Device\HarddiskVolume3\Program Files\Git\cmd\git.exe`})
	if r := escalate(a, ruleFor("bam")); r.Severity != SevInfo {
		t.Fatalf("Severity = %s, want INFO", r.Severity)
	}
}

// TestTimestompIsPlacedAtTheRealDate: con timestomping, SI.Created es el
// valor que escribió quien es revisado. El hallazgo tiene que ubicarse donde
// el archivo apareció de verdad (FN.Created), no donde esa persona quiso.
func TestTimestompIsPlacedAtTheRealDate(t *testing.T) {
	now := time.Date(2026, 9, 18, 15, 0, 0, 0, time.UTC)
	forged := time.Date(2019, 1, 1, 0, 0, 0, 0, time.UTC)
	real := now.Add(-2 * time.Hour)
	payload := map[string]any{
		"SI":      map[string]any{"Created": forged},
		"FN":      map[string]any{"Created": real},
		"Verdict": map[string]any{"Stomped": true},
	}
	for _, typ := range []string{"mft_timestomp", "deleted_entry"} {
		a := art(typ, `C:\Users\x\Desktop\tool.exe`, payload)
		got, ok := timeOf(a)
		if !ok || !got.Equal(real) {
			t.Errorf("%s: timeOf = %v, want la fecha real %v", typ, got, real)
		}
		act := Activity([]collector.Result{{Collector: "c", Artifacts: []collector.Artifact{a}}}, now)
		if n := sum(act.Channels[ChannelFiles]); n != 1 {
			t.Errorf("%s: el registro de actividad cuenta %d, want 1", typ, n)
		}
	}
}

func TestDeletedEntryWithoutStompKeepsSICreated(t *testing.T) {
	si := time.Date(2026, 9, 1, 10, 0, 0, 0, time.UTC)
	a := art("deleted_entry", `C:\x\y.exe`, map[string]any{
		"SI":      map[string]any{"Created": si},
		"FN":      map[string]any{"Created": si.Add(-24 * time.Hour)},
		"Verdict": map[string]any{"Stomped": false},
	})
	if got, ok := timeOf(a); !ok || !got.Equal(si) {
		t.Fatalf("timeOf = %v, want SI.Created %v", got, si)
	}
}

func TestTimestompWithoutFNFallsBackToSI(t *testing.T) {
	si := time.Date(2026, 9, 1, 10, 0, 0, 0, time.UTC)
	a := art("mft_timestomp", `C:\x\y.exe`, map[string]any{"SI": map[string]any{"Created": si}})
	if got, ok := timeOf(a); !ok || !got.Equal(si) {
		t.Fatalf("timeOf = %v, want %v", got, si)
	}
}
