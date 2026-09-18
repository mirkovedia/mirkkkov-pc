package authenticode

import "testing"

func TestVerifyEmptyPathIsUnknown(t *testing.T) {
	r := Verify("   ")
	if r.Status != StatusUnknown {
		t.Fatalf("Status = %s, want unknown", r.Status)
	}
}

func TestVerifyMissingFileIsUnknownNotUnsigned(t *testing.T) {
	// Un archivo que no existe no es "sin firma": es "no sé". Confundirlos
	// convierte un borrado en una acusación.
	r := Verify(`C:\no\existe\nunca\x.sys`)
	if r.Status != StatusUnknown {
		t.Fatalf("Status = %s, want unknown (%s)", r.Status, r.Detail)
	}
}

func TestVerifyCachesByPathCaseInsensitive(t *testing.T) {
	ResetCache()
	cache.Store(`c:\fake\a.exe`, Result{Status: StatusSigned, Signer: "cache"})
	if r := Verify(`C:\FAKE\A.EXE`); r.Signer != "cache" {
		t.Fatalf("la caché debe ser insensible a mayúsculas: %+v", r)
	}
	ResetCache()
}

func TestIsTrusted(t *testing.T) {
	if !(Result{Status: StatusSigned}).IsTrusted() {
		t.Fatal("signed debe ser confiable")
	}
	for _, s := range []Status{StatusUnsigned, StatusInvalid, StatusUnknown} {
		if (Result{Status: s}).IsTrusted() {
			t.Fatalf("%s no debe ser confiable", s)
		}
	}
}
