//go:build windows

package mft

import (
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/windows"
)

// TestGetFileRecordReadsRealFile pide a NTFS el registro de un archivo real y
// comprueba que parsea. Requiere elevación (abrir el volumen en crudo), así
// que en una consola normal se salta; en el runner de CI, que corre elevado,
// es el test que habría detectado que getFileRecord fallaba SIEMPRE.
//
// TestScanTimestompIntegration no lo veía: valida la forma de los hallazgos,
// y cero hallazgos tiene buena forma.
func TestGetFileRecordReadsRealFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "registro_real.exe")
	if err := os.WriteFile(path, []byte("MZ"), 0o600); err != nil {
		t.Fatal(err)
	}

	vol, err := windows.UTF16PtrFromString(`\\.\` + filepath.VolumeName(path))
	if err != nil {
		t.Fatal(err)
	}
	h, err := windows.CreateFile(vol, windows.GENERIC_READ,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, nil, windows.OPEN_EXISTING, 0, 0)
	if err != nil {
		t.Skipf("volumen no accesible en crudo (¿sin elevación?): %v", err)
	}
	defer windows.CloseHandle(h)

	p, _ := windows.UTF16PtrFromString(path)
	fh, err := windows.CreateFile(p, 0,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil, windows.OPEN_EXISTING, windows.FILE_FLAG_BACKUP_SEMANTICS, 0)
	if err != nil {
		t.Fatal(err)
	}
	var info windows.ByHandleFileInformation
	err = windows.GetFileInformationByHandle(fh, &info)
	windows.CloseHandle(fh)
	if err != nil {
		t.Fatal(err)
	}
	ref := uint64(info.FileIndexHigh)<<32 | uint64(info.FileIndexLow)

	rec, err := getFileRecord(h, ref)
	if err != nil {
		t.Fatalf("getFileRecord sobre un archivo real: %v", err)
	}
	if !rec.HasSI || !rec.HasFN {
		t.Fatalf("registro sin SI o FN: %+v", rec)
	}
	if rec.FileName != "registro_real.exe" && rec.FileName != "REGIST~1.EXE" {
		t.Fatalf("FileName = %q", rec.FileName)
	}
}
