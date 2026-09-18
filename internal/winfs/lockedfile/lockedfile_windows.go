//go:build windows

package lockedfile

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/windows"

	winmft "github.com/mirkovedia/mirkkkov-pc/internal/winfs/mft"
	"github.com/mirkovedia/mirkkkov-pc/internal/winfs/ntfs"
)

const fsctlGetNtfsFileRecord = 0x00090068

// mftEntryMask aísla el nº de entrada MFT (48 bits bajos) del file reference.
const mftEntryMask = 0x0000FFFFFFFFFFFF

// CopyTo copia src a dst. Primero intenta la copia normal; si el archivo está
// tomado en exclusiva (el caso de los hives en uso), lo lee por acceso raw al
// volumen. Requiere privilegios de administrador para el camino raw.
func CopyTo(src, dst string) error {
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer out.Close()
	if in, err := os.Open(src); err == nil {
		defer in.Close()
		_, err = io.Copy(out, in)
		return err
	} else if !isLocked(err) {
		return err
	}
	return rawCopy(src, out)
}

// ReadFile lee src entero en memoria, con la misma degradación que CopyTo.
func ReadFile(src string) ([]byte, error) {
	data, err := os.ReadFile(src)
	if err == nil || !isLocked(err) {
		return data, err
	}
	var buf bytesWriter
	if err := rawCopy(src, &buf); err != nil {
		return nil, err
	}
	return buf.b, nil
}

type bytesWriter struct{ b []byte }

func (w *bytesWriter) Write(p []byte) (int, error) {
	w.b = append(w.b, p...)
	return len(p), nil
}

// isLocked reporta si el error de apertura es el de un archivo tomado por
// otro proceso. Access denied también entra: los hives montados devuelven
// una u otra según la versión de Windows.
func isLocked(err error) bool {
	return errors.Is(err, windows.ERROR_SHARING_VIOLATION) || errors.Is(err, windows.ERROR_ACCESS_DENIED)
}

// rawCopy lee src por acceso raw y lo escribe en w.
func rawCopy(src string, w io.Writer) error {
	abs, err := filepath.Abs(src)
	if err != nil {
		return err
	}
	ref, err := fileReference(abs)
	if err != nil {
		return fmt.Errorf("obtener el registro MFT de %s: %w", src, err)
	}
	vol, err := openVolume(filepath.VolumeName(abs))
	if err != nil {
		return err
	}
	defer vol.Close()

	rec, err := vol.fileRecord(ref)
	if err != nil {
		return fmt.Errorf("leer el registro MFT de %s: %w", src, err)
	}
	layout, err := parseDataLayout(rec)
	if err != nil {
		return fmt.Errorf("%s: %w", src, err)
	}
	return copyData(vol, layout, w)
}

// fileReference devuelve el file reference (nº de registro MFT + secuencia)
// de un archivo, aunque esté abierto en exclusiva por otro proceso. Abrir con
// acceso 0 no compite con el modo de compartición de nadie: solo permite
// consultar metadatos, que es exactamente lo que hace falta.
func fileReference(path string) (uint64, error) {
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return 0, err
	}
	var h windows.Handle
	for _, access := range []uint32{0, windows.FILE_READ_ATTRIBUTES} {
		h, err = windows.CreateFile(p, access,
			windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
			nil, windows.OPEN_EXISTING, windows.FILE_FLAG_BACKUP_SEMANTICS, 0)
		if err == nil {
			break
		}
	}
	if err != nil {
		return 0, err
	}
	defer windows.CloseHandle(h)
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(h, &info); err != nil {
		return 0, err
	}
	return uint64(info.FileIndexHigh)<<32 | uint64(info.FileIndexLow), nil
}

// winVolume es un volumen NTFS abierto en crudo.
type winVolume struct {
	h       windows.Handle
	cluster int
	record  int
}

// openVolume abre "\\.\C:" a partir de "C:" y lee su geometría del boot sector.
func openVolume(letter string) (*winVolume, error) {
	letter = strings.TrimSuffix(letter, `\`)
	if len(letter) != 2 || letter[1] != ':' {
		return nil, fmt.Errorf("volumen inválido %q", letter)
	}
	p, err := windows.UTF16PtrFromString(`\\.\` + letter)
	if err != nil {
		return nil, err
	}
	h, err := windows.CreateFile(p, windows.GENERIC_READ,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE,
		nil, windows.OPEN_EXISTING, 0, 0)
	if err != nil {
		return nil, fmt.Errorf("abrir el volumen %s en crudo (¿sin privilegios de administrador?): %w", letter, err)
	}
	v := &winVolume{h: h}
	sector := make([]byte, 512)
	if err := v.ReadAt(0, sector); err != nil {
		v.Close()
		return nil, fmt.Errorf("leer boot sector: %w", err)
	}
	boot, err := ntfs.ParseBootSector(sector)
	if err != nil {
		v.Close()
		return nil, err
	}
	v.cluster = boot.ClusterSize
	v.record = boot.BytesPerRecord
	return v, nil
}

func (v *winVolume) Close() error    { return windows.CloseHandle(v.h) }
func (v *winVolume) ClusterSize() int { return v.cluster }

// ReadAt lee len(buf) bytes en offset usando OVERLAPPED como posición
// explícita; offset y len(buf) deben estar alineados a sector.
func (v *winVolume) ReadAt(offset int64, buf []byte) error {
	var ov windows.Overlapped
	ov.Offset = uint32(offset & 0xFFFFFFFF)
	ov.OffsetHigh = uint32(offset >> 32)
	var done uint32
	if err := windows.ReadFile(v.h, buf, &done, &ov); err != nil {
		return err
	}
	if int(done) != len(buf) {
		return fmt.Errorf("lectura corta: %d de %d bytes", done, len(buf))
	}
	return nil
}

// fileRecord pide a NTFS el registro MFT del file reference y devuelve sus
// bytes con el fixup aplicado, listos para parsear atributos.
func (v *winVolume) fileRecord(ref uint64) ([]byte, error) {
	in := make([]byte, 8)
	binary.LittleEndian.PutUint64(in, ref)
	out := make([]byte, 12+v.record+4096)
	var ret uint32
	if err := windows.DeviceIoControl(v.h, fsctlGetNtfsFileRecord,
		&in[0], uint32(len(in)), &out[0], uint32(len(out)), &ret, nil); err != nil {
		return nil, fmt.Errorf("GET_NTFS_FILE_RECORD: %w", err)
	}
	if ret < 12 {
		return nil, errors.New("respuesta MFT muy corta")
	}
	if got := binary.LittleEndian.Uint64(out[0:8]); got&mftEntryMask != ref&mftEntryMask {
		return nil, errors.New("NTFS devolvió otro registro: el archivo ya no está en uso")
	}
	recLen := int(binary.LittleEndian.Uint32(out[8:12]))
	if recLen <= 0 || 12+recLen > int(ret) {
		return nil, errors.New("FileRecordLength fuera de rango")
	}
	return winmft.ApplyFixup(out[12 : 12+recLen])
}
