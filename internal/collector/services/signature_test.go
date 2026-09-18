package services

import (
	"encoding/json"
	"testing"

	"github.com/mirkovedia/mirkkkov-pc/internal/winfs/authenticode"
	winservices "github.com/mirkovedia/mirkkkov-pc/internal/winfs/services"
)

// TestEnrichVerifiesNormalizedPath: el registro guarda "\??\C:\Windows\x.sys"
// o "\SystemRoot\...", pero lo que hay que abrir para verificar la firma es
// la ruta real. Y la firma tiene que salir en el JSON junto a los campos del
// servicio, que el motor de severidad lee al tope.
func TestEnrichVerifiesNormalizedPath(t *testing.T) {
	var asked string
	c := New("")
	c.Verify = func(path string) authenticode.Result {
		asked = path
		return authenticode.Result{Status: authenticode.StatusSigned, Signer: "Wellbia.com Co., Ltd."}
	}
	art := c.enrich(winservices.DriverService{Name: "xhunter1", ImagePath: `\??\C:\Windows\xhunter1.sys`, Type: 1})
	if asked != `c:\windows\xhunter1.sys` {
		t.Fatalf("se verificó %q, want la ruta normalizada", asked)
	}
	raw, _ := json.Marshal(art)
	var got struct {
		ImagePath string
		Signature struct{ Status, Signer string }
	}
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatal(err)
	}
	if got.ImagePath != `\??\C:\Windows\xhunter1.sys` || got.Signature.Status != "signed" || got.Signature.Signer == "" {
		t.Fatalf("JSON = %s", raw)
	}
}

func TestEnrichWithoutVerifierIsUnknown(t *testing.T) {
	c := &Collector{}
	art := c.enrich(winservices.DriverService{ImagePath: `C:\x.sys`})
	if art.Signature.Status != authenticode.StatusUnknown {
		t.Fatalf("Status = %s, want unknown", art.Signature.Status)
	}
}
