package verdict

import (
	"errors"
	"testing"
	"time"

	"github.com/mirkovedia/mirkkkov-pc/internal/collector"
)

func sum(xs []int) int {
	n := 0
	for _, x := range xs {
		n += x
	}
	return n
}

func TestActivityAlwaysHasThreeChannels(t *testing.T) {
	act := Activity(nil, time.Now())
	for _, ch := range []string{ChannelExecution, ChannelFiles, ChannelSession} {
		if len(act.Channels[ch]) != ActivityDays*24 {
			t.Fatalf("canal %s: len = %d", ch, len(act.Channels[ch]))
		}
	}
	if act.BucketMinutes != 60 {
		t.Fatalf("BucketMinutes = %d", act.BucketMinutes)
	}
}

// TestActivityBucketsByHourAndChannel: la última hora cae en el último
// bucket, cada tipo va a su canal y la evidencia neutra también cuenta (es la
// mayor parte de la actividad de una máquina normal).
func TestActivityBucketsByHourAndChannel(t *testing.T) {
	now := time.Date(2026, 9, 18, 15, 30, 0, 0, time.UTC)
	results := []collector.Result{
		{Collector: "bam", Artifacts: []collector.Artifact{
			art("bam", "x", map[string]any{"lastExecution": now.Add(-10 * time.Minute)}),
			art("bam", "y", map[string]any{"lastExecution": now.Add(-26 * time.Hour)}),
		}},
		{Collector: "usn", Artifacts: []collector.Artifact{
			art("usn", "z.exe", map[string]any{"Timestamp": now.Add(-20 * time.Minute)}),
		}},
		{Collector: "eventlog", Artifacts: []collector.Artifact{
			art("eventlog.session_timeline", "Security", map[string]any{"time": now.Add(-5 * time.Minute)}),
		}},
		{Collector: "services", Artifacts: []collector.Artifact{
			art("service_driver", "d.sys", map[string]any{"ImagePath": "d.sys"}), // sin fecha: ningún canal
		}},
	}
	act := Activity(results, now)
	last := ActivityDays*24 - 1
	if act.Channels[ChannelExecution][last] != 1 || act.Channels[ChannelExecution][last-26] != 1 {
		t.Fatalf("execution mal ubicado: último=%d", act.Channels[ChannelExecution][last])
	}
	if act.Channels[ChannelFiles][last] != 1 || act.Channels[ChannelSession][last] != 1 {
		t.Fatal("files o session mal ubicados")
	}
	if got := sum(act.Channels[ChannelExecution]); got != 2 {
		t.Fatalf("execution total = %d, want 2", got)
	}
	// El primer bucket empieza exactamente ActivityDays*24-1 horas antes de la
	// hora en curso.
	wantFrom := now.Truncate(time.Hour).Add(-time.Duration(last) * time.Hour)
	if !act.From.Equal(wantFrom) {
		t.Fatalf("From = %v, want %v", act.From, wantFrom)
	}
}

func TestActivityCountsEveryPrefetchRun(t *testing.T) {
	now := time.Date(2026, 9, 18, 15, 0, 0, 0, time.UTC)
	runs := []time.Time{now.Add(-1 * time.Hour), now.Add(-2 * time.Hour), now.Add(-50 * time.Hour), {}}
	results := []collector.Result{{Collector: "prefetch", Artifacts: []collector.Artifact{
		art("prefetch", `C:\Windows\Prefetch\GAME.EXE-1.pf`, map[string]any{"LastRunTimes": runs}),
	}}}
	if got := sum(Activity(results, now).Channels[ChannelExecution]); got != 3 {
		t.Fatalf("ejecuciones contadas = %d, want 3 (la fecha cero no cuenta)", got)
	}
}

func TestActivityIgnoresOutOfWindowAndFailedCollectors(t *testing.T) {
	now := time.Date(2026, 9, 18, 15, 0, 0, 0, time.UTC)
	results := []collector.Result{
		{Collector: "usn", Artifacts: []collector.Artifact{
			art("usn", "viejo.exe", map[string]any{"Timestamp": now.Add(-40 * 24 * time.Hour)}),
			art("usn", "futuro.exe", map[string]any{"Timestamp": now.Add(3 * time.Hour)}),
		}},
		{Collector: "bam", Err: errors.New("hive ilegible"), Artifacts: []collector.Artifact{
			art("bam", "x", map[string]any{"lastExecution": now}),
		}},
	}
	act := Activity(results, now)
	if sum(act.Channels[ChannelFiles]) != 0 || sum(act.Channels[ChannelExecution]) != 0 {
		t.Fatalf("no debería contarse nada: %d / %d", sum(act.Channels[ChannelFiles]), sum(act.Channels[ChannelExecution]))
	}
}

// TestActivityAlignsBucketsToLocalHour: en un huso de media hora (India,
// UTC+5:30) los buckets tienen que empezar en la hora local en punto, que en
// UTC cae a y media. Alineados a UTC, cada barra quedaba corrida media hora
// respecto de las horas que dibuja la interfaz.
func TestActivityAlignsBucketsToLocalHour(t *testing.T) {
	ist := time.FixedZone("IST", 5*3600+30*60)
	now := time.Date(2026, 9, 18, 15, 40, 0, 0, ist)
	act := Activity(nil, now)
	if m := act.From.In(ist).Minute(); m != 0 {
		t.Fatalf("el primer bucket empieza al minuto %d de la hora local, want 0", m)
	}
	// El último bucket es la hora local en curso: 15:00 a 16:00 IST.
	last := act.From.Add(time.Duration(ActivityDays*24-1) * time.Hour).In(ist)
	if last.Hour() != 15 || last.Minute() != 0 {
		t.Fatalf("último bucket = %v, want 15:00 IST", last)
	}
	// Un hecho a las 15:10 locales cae en ese último bucket; con la
	// alineación a UTC (límite en 15:30 local) caía en el anterior.
	results := []collector.Result{{Collector: "bam", Artifacts: []collector.Artifact{
		art("bam", "x", map[string]any{"lastExecution": time.Date(2026, 9, 18, 15, 10, 0, 0, ist)}),
	}}}
	got := Activity(results, now).Channels[ChannelExecution]
	if got[len(got)-1] != 1 {
		t.Fatal("un hecho de la hora local en curso debe caer en el último bucket")
	}
}
