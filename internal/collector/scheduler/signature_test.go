package scheduler

import (
	"encoding/json"
	"testing"

	"github.com/mirkovedia/mirkkkov-pc/internal/winfs/authenticode"
	winscheduler "github.com/mirkovedia/mirkkkov-pc/internal/winfs/scheduler"
)

// TestEnrichAttachesSignatureOfCommand: la tarea oculta del actualizador de
// Google fue un MEDIUM del reporte real. Con la firma del ejecutable en el
// JSON, el motor puede bajarla a INFO sin allowlists por nombre.
func TestEnrichAttachesSignatureOfCommand(t *testing.T) {
	var asked string
	c := newCollector("", "")
	c.Verify = func(p string) authenticode.Result {
		asked = p
		return authenticode.Result{Status: authenticode.StatusSigned, Signer: "Google LLC"}
	}
	task := winscheduler.TaskDefinition{
		RelPath: `GoogleSystem\GoogleUpdater\GoogleUpdaterTaskSystem`,
		Command: `"C:\Program Files (x86)\Google\GoogleUpdater\updater.exe"`,
		Hidden:  true,
	}
	raw, _ := json.Marshal(c.enrich(task))
	if asked != `C:\Program Files (x86)\Google\GoogleUpdater\updater.exe` {
		t.Fatalf("se verificó %q", asked)
	}
	var got struct {
		RelPath   string
		Hidden    bool
		Signature struct{ Status, Signer string }
	}
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatal(err)
	}
	if !got.Hidden || got.RelPath == "" || got.Signature.Status != "signed" || got.Signature.Signer != "Google LLC" {
		t.Fatalf("JSON = %s", raw)
	}
}

func TestEnrichUnverifiableCommandIsUnknown(t *testing.T) {
	c := newCollector("", "")
	c.Verify = func(string) authenticode.Result { t.Fatal("no debe llamarse"); return authenticode.Result{} }
	art := c.enrich(winscheduler.TaskDefinition{Command: "cmd.exe", Hidden: true})
	if art.Signature.Status != authenticode.StatusUnknown {
		t.Fatalf("Status = %s", art.Signature.Status)
	}
}
