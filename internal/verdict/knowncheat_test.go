package verdict

import (
	"strings"
	"testing"

	"github.com/mirkovedia/mirkkkov-pc/internal/collector"
	"github.com/mirkovedia/mirkkkov-pc/internal/report"
)

const testHash = "da39a3ee5e6b4b0d3255bfef95601890afd80709" // SHA-1 de "" (vacío)

func withKnownCheat(t *testing.T) {
	t.Helper()
	before := KnownCheatCount()
	AddKnownCheats(strings.NewReader("# comentario\n\n" + strings.ToUpper(testHash) + " FF Loader v3\nzzzz no-es-hash\n"))
	if KnownCheatCount() != before+1 {
		t.Fatalf("se esperaba 1 hash nuevo, hay %d", KnownCheatCount()-before)
	}
	t.Cleanup(func() {
		knownCheatsMu.Lock()
		delete(knownCheats, testHash)
		knownCheatsMu.Unlock()
	})
}

func TestEmbeddedListShipsWithoutHashes(t *testing.T) {
	// La lista embebida es solo formato y comentarios: los hashes reales
	// los pone quien opera el agente.
	if n := len(parseKnownCheats(strings.NewReader(knownCheatHashes))); n != 0 {
		t.Fatalf("la lista embebida no debería traer hashes, tiene %d", n)
	}
}

func TestKnownCheatLookupIsCaseInsensitive(t *testing.T) {
	withKnownCheat(t)
	if name, ok := KnownCheat(strings.ToUpper(testHash)); !ok || name != "FF Loader v3" {
		t.Fatalf("KnownCheat = %q, %v", name, ok)
	}
	if _, ok := KnownCheat("0000000000000000000000000000000000000000"); ok {
		t.Fatal("un hash desconocido no debe matchear")
	}
}

// TestAmcacheHashMatchIsCriticalKnownCheat: Amcache guarda el SHA-1 de cada
// ejecutable que corrió, aunque ya no exista. Un match con la lista es la
// afirmación más fuerte que el motor puede hacer.
func TestAmcacheHashMatchIsCriticalKnownCheat(t *testing.T) {
	withKnownCheat(t)
	a := art("amcache", `C:\Windows\appcompat\Programs\Amcache.hve`, map[string]any{
		"sha1": testHash, "path": `c:\users\x\downloads\ff.exe`,
	})
	got := escalate(a, ruleFor("amcache"))
	if got.Category != CatKnownCheat || got.Severity != SevCritical {
		t.Fatalf("rule = %+v", got)
	}
	if title := titleOf(a); !strings.Contains(title, "FF Loader v3") {
		t.Fatalf("title = %q", title)
	}
	findings, v := Evaluate([]collector.Result{{Collector: "amcache", Artifacts: []collector.Artifact{a}}})
	if v.Level != report.LevelEvidenciaFuerte {
		t.Fatalf("Level = %s", v.Level)
	}
	if findings[0].Artifact != `c:\users\x\downloads\ff.exe` {
		t.Fatalf("el hallazgo debe apuntar al ejecutable, no al hive: %q", findings[0].Artifact)
	}
}

func TestAmcacheWithoutMatchStaysNeutral(t *testing.T) {
	a := art("amcache", `C:\Windows\appcompat\Programs\Amcache.hve`, map[string]any{
		"sha1": "0000000000000000000000000000000000000000", "path": `c:\program files\git\git.exe`,
	})
	if got := escalate(a, ruleFor("amcache")); got.Severity != SevInfo {
		t.Fatalf("Severity = %s", got.Severity)
	}
}
