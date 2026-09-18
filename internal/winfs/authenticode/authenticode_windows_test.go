//go:build windows

package authenticode

import (
	"os"
	"testing"
)

// TestSystemFilesAreSigned: los binarios del sistema tienen que verificar,
// vengan con firma embebida (cada vez más en Windows 11) o por catálogo.
func TestSystemFilesAreSigned(t *testing.T) {
	ResetCache()
	for _, p := range []string{`C:\Windows\System32\kernel32.dll`, `C:\Windows\System32\ntdll.dll`, `C:\Windows\explorer.exe`} {
		if _, err := os.Stat(p); err != nil {
			continue
		}
		if r := Verify(p); r.Status != StatusSigned {
			t.Errorf("%s: Status = %s (%s), want signed", p, r.Status, r.Detail)
		}
	}
}

// TestCatalogPathResolvesSomeSystemFile recorre varios archivos del sistema
// hasta encontrar uno firmado SOLO por catálogo, que es el camino que ejercita
// las APIs de CryptCAT. Se salta si en esta instalación todos vienen con
// firma embebida.
func TestCatalogPathResolvesSomeSystemFile(t *testing.T) {
	ResetCache()
	candidates := []string{
		`C:\Windows\System32\drivers\ndis.sys`,
		`C:\Windows\System32\drivers\tcpip.sys`,
		`C:\Windows\System32\drivers\ntfs.sys`,
		`C:\Windows\System32\msvcrt.dll`,
		`C:\Windows\System32\wintrust.dll`,
		`C:\Windows\System32\crypt32.dll`,
		`C:\Windows\System32\shell32.dll`,
		`C:\Windows\System32\cmd.exe`,
		`C:\Windows\System32\calc.exe`,
	}
	for _, p := range candidates {
		if _, err := os.Stat(p); err != nil {
			continue
		}
		r := Verify(p)
		if r.Status == StatusSigned && r.Catalog {
			t.Logf("%s verificado por catálogo", p)
			return
		}
		if r.Status != StatusSigned {
			t.Errorf("%s: Status = %s (%s), want signed", p, r.Status, r.Detail)
		}
	}
	t.Skip("ningún candidato se firma solo por catálogo en esta instalación")
}

// TestUnsignedTestBinary: el binario de test que compila `go test` no está
// firmado por nadie. Es el negativo determinista.
func TestUnsignedTestBinary(t *testing.T) {
	ResetCache()
	exe, err := os.Executable()
	if err != nil {
		t.Skip(err)
	}
	r := Verify(exe)
	if r.Status != StatusUnsigned {
		t.Fatalf("binario de test: Status = %s (%s), want unsigned", r.Status, r.Detail)
	}
}

// TestEmbeddedSignedFile busca algún binario con firma embebida presente en
// la máquina y comprueba que se resuelve el firmante. Se salta si no hay
// ninguno: no se puede asumir software de terceros en CI.
func TestEmbeddedSignedFile(t *testing.T) {
	ResetCache()
	candidates := []string{
		`C:\Windows\xhunter1.sys`,
		`C:\Program Files\nodejs\node.exe`,
		`C:\Program Files\PowerShell\7\pwsh.exe`,
		`C:\Program Files\Git\cmd\git.exe`,
		`C:\Program Files\Microsoft VS Code\Code.exe`,
	}
	for _, c := range candidates {
		if _, err := os.Stat(c); err != nil {
			continue
		}
		r := Verify(c)
		if r.Status != StatusSigned {
			t.Logf("%s: %s (%s)", c, r.Status, r.Detail)
			continue
		}
		if r.Catalog {
			continue // firmado, pero por catálogo: no sirve para este test
		}
		if r.Signer == "" {
			t.Fatalf("%s: firma embebida válida pero sin firmante resuelto", c)
		}
		t.Logf("%s firmado por %q", c, r.Signer)
		return
	}
	t.Skip("no hay binarios con firma embebida conocidos en esta máquina")
}

// TestCorruptedCopyIsInvalid: una copia con un byte cambiado de un archivo
// firmado tiene firma pero no verifica.
func TestCorruptedCopyIsInvalid(t *testing.T) {
	ResetCache()
	src := ""
	for _, c := range []string{`C:\Windows\xhunter1.sys`, `C:\Program Files\nodejs\node.exe`, `C:\Program Files\Git\cmd\git.exe`} {
		if _, err := os.Stat(c); err == nil {
			if r := Verify(c); r.Status == StatusSigned && !r.Catalog {
				src = c
				break
			}
		}
	}
	if src == "" {
		t.Skip("sin archivo con firma embebida para corromper")
	}
	data, err := os.ReadFile(src)
	if err != nil {
		t.Fatal(err)
	}
	data[len(data)/2]++
	dst := t.TempDir() + `\corrupto.bin`
	if err := os.WriteFile(dst, data, 0o600); err != nil {
		t.Fatal(err)
	}
	r := Verify(dst)
	if r.Status != StatusInvalid {
		t.Fatalf("copia corrupta: Status = %s (%s), want invalid", r.Status, r.Detail)
	}
}
