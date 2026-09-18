package eventlog

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/mirkovedia/mirkkkov-pc/internal/winfs/evtx/evtxtest"
)

// TestTimeChangeFromSystemServiceIsLegit: el servicio de hora ajusta el
// reloj varias veces al día; un 4616 de svchost.exe no puede ser señal.
func TestTimeChangeFromSystemServiceIsLegit(t *testing.T) {
	ts := time.Now().UTC()
	prev := ts.Add(-2 * time.Second)
	sec := evtxtest.NewBuilder().
		AddRecord(1, ts, 4616, []evtxtest.Sub{
			evtxtest.StringSub("SYSTEM"), evtxtest.StringSub("NT AUTHORITY"),
			evtxtest.FileTimeSub(prev), evtxtest.FileTimeSub(ts),
			evtxtest.StringSub(`C:\Windows\System32\svchost.exe`),
		}).
		AddRecord(2, ts.Add(time.Minute), 4616, []evtxtest.Sub{
			evtxtest.StringSub("jugador"), evtxtest.StringSub("PC"),
			evtxtest.FileTimeSub(ts.Add(time.Minute)), evtxtest.FileTimeSub(ts.Add(-30 * 24 * time.Hour)),
			evtxtest.StringSub(`C:\Windows\ImmersiveControlPanel\SystemSettings.exe`),
		}).
		Build()
	path := writeEvtx(t, "Security.evtx", sec)

	arts, err := New(path, "", "", "", "").Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	var got []timeChange
	for _, a := range arts {
		if a.Type == "eventlog.time_changed" {
			var tc timeChange
			if err := json.Unmarshal(a.Data, &tc); err != nil {
				t.Fatal(err)
			}
			got = append(got, tc)
		}
	}
	if len(got) != 2 {
		t.Fatalf("time_changed = %d", len(got))
	}
	if !got[0].Legit || got[0].Process == "" {
		t.Fatalf("svchost debe ser legítimo: %+v", got[0])
	}
	if got[1].Legit || got[1].New.IsZero() || got[1].Previous.IsZero() {
		t.Fatalf("SystemSettings es un cambio manual con fechas: %+v", got[1])
	}
}
