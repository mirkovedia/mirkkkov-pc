package lockedfile

import (
	"bytes"
	"encoding/binary"
	"errors"
	"testing"

	"github.com/mirkovedia/mirkkkov-pc/internal/winfs/ntfs"
)

// residentData arma un atributo $DATA residente con el contenido dado.
func residentData(content []byte) []byte {
	const hdr = 0x18
	total := hdr + len(content)
	if total%8 != 0 {
		total += 8 - total%8
	}
	a := make([]byte, total)
	binary.LittleEndian.PutUint32(a[0:4], attrData)
	binary.LittleEndian.PutUint32(a[4:8], uint32(total))
	a[8] = 0
	binary.LittleEndian.PutUint32(a[0x10:0x14], uint32(len(content)))
	binary.LittleEndian.PutUint16(a[0x14:0x16], hdr)
	copy(a[hdr:], content)
	return a
}

// nonResidentData arma un atributo $DATA no residente con los data runs y
// tamaño real dados. flags permite simular compresión/sparse.
func nonResidentData(runs []byte, realSize uint64, flags uint16) []byte {
	const hdr = 0x40
	total := hdr + len(runs)
	if total%8 != 0 {
		total += 8 - total%8
	}
	a := make([]byte, total)
	binary.LittleEndian.PutUint32(a[0:4], attrData)
	binary.LittleEndian.PutUint32(a[4:8], uint32(total))
	a[8] = 1
	binary.LittleEndian.PutUint16(a[0x0C:0x0E], flags)
	binary.LittleEndian.PutUint16(a[0x20:0x22], hdr)
	binary.LittleEndian.PutUint64(a[0x30:0x38], realSize)
	copy(a[hdr:], runs)
	return a
}

// emptyAttr arma un atributo residente vacío de un tipo dado (para simular
// un $ATTRIBUTE_LIST en el registro).
func emptyAttr(attrType uint32) []byte {
	a := make([]byte, 0x18)
	binary.LittleEndian.PutUint32(a[0:4], attrType)
	binary.LittleEndian.PutUint32(a[4:8], 0x18)
	binary.LittleEndian.PutUint16(a[0x14:0x16], 0x18)
	return a
}

// record arma un registro FILE de 1024 bytes ya con fixup aplicado (los
// tests de acá no prueban el fixup: eso es del paquete mft).
func record(attrs ...[]byte) []byte {
	const firstAttr = 0x38
	r := make([]byte, 1024)
	copy(r[0:4], "FILE")
	binary.LittleEndian.PutUint16(r[0x14:0x16], firstAttr)
	off := firstAttr
	for _, a := range attrs {
		copy(r[off:], a)
		off += len(a)
	}
	binary.LittleEndian.PutUint32(r[off:off+4], attrTerminator)
	return r
}

func TestParseDataLayoutResident(t *testing.T) {
	want := []byte("regf hive chico")
	layout, err := parseDataLayout(record(residentData(want)))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(layout.resident, want) || layout.size != uint64(len(want)) {
		t.Fatalf("layout = %+v", layout)
	}
}

func TestParseDataLayoutNonResident(t *testing.T) {
	// Un run de 3 clústers desde el LCN 10, luego 2 clústers en LCN 20.
	runs := []byte{0x11, 0x03, 0x0A, 0x11, 0x02, 0x0A, 0x00}
	layout, err := parseDataLayout(record(nonResidentData(runs, 4096*5-100, 0)))
	if err != nil {
		t.Fatal(err)
	}
	wantExt := []ntfs.Extent{{StartLCN: 10, Length: 3}, {StartLCN: 20, Length: 2}}
	if len(layout.extents) != 2 || layout.extents[0] != wantExt[0] || layout.extents[1] != wantExt[1] {
		t.Fatalf("extents = %+v, want %+v", layout.extents, wantExt)
	}
	if layout.size != 4096*5-100 {
		t.Fatalf("size = %d", layout.size)
	}
}

func TestParseDataLayoutRejectsCompressed(t *testing.T) {
	runs := []byte{0x11, 0x01, 0x05, 0x00}
	_, err := parseDataLayout(record(nonResidentData(runs, 100, attrFlagCompressed)))
	if !errors.Is(err, ErrUnsupportedLayout) {
		t.Fatalf("err = %v, want ErrUnsupportedLayout", err)
	}
}

func TestParseDataLayoutRejectsAttributeListWithoutData(t *testing.T) {
	_, err := parseDataLayout(record(emptyAttr(attrAttributeList)))
	if !errors.Is(err, ErrUnsupportedLayout) {
		t.Fatalf("err = %v, want ErrUnsupportedLayout", err)
	}
}

func TestParseDataLayoutNoData(t *testing.T) {
	if _, err := parseDataLayout(record()); !errors.Is(err, ErrNoData) {
		t.Fatalf("err = %v, want ErrNoData", err)
	}
}

// memVolume es una imagen de disco en memoria.
type memVolume struct {
	data    []byte
	cluster int
}

func (m *memVolume) ClusterSize() int { return m.cluster }
func (m *memVolume) ReadAt(off int64, buf []byte) error {
	if off < 0 || int(off)+len(buf) > len(m.data) {
		return errors.New("lectura fuera de la imagen")
	}
	copy(buf, m.data[off:int(off)+len(buf)])
	return nil
}

func TestCopyDataWalksExtentsAndTruncates(t *testing.T) {
	const cluster = 512
	vol := &memVolume{data: make([]byte, cluster*64), cluster: cluster}
	// Contenido: clústers 10-12 = "AAAA…", clústers 20-21 = "BBBB…".
	for i := 10 * cluster; i < 13*cluster; i++ {
		vol.data[i] = 'A'
	}
	for i := 20 * cluster; i < 22*cluster; i++ {
		vol.data[i] = 'B'
	}
	layout := dataLayout{
		extents: []ntfs.Extent{{StartLCN: 10, Length: 3}, {StartLCN: 20, Length: 2}},
		size:    cluster*5 - 100, // el último clúster sobra parcialmente
	}
	var out bytes.Buffer
	if err := copyData(vol, layout, &out); err != nil {
		t.Fatal(err)
	}
	got := out.Bytes()
	if len(got) != cluster*5-100 {
		t.Fatalf("len = %d, want %d", len(got), cluster*5-100)
	}
	if got[0] != 'A' || got[3*cluster-1] != 'A' || got[3*cluster] != 'B' || got[len(got)-1] != 'B' {
		t.Fatal("el contenido no sigue el orden de los extents")
	}
}

func TestCopyDataResident(t *testing.T) {
	var out bytes.Buffer
	if err := copyData(&memVolume{cluster: 512}, dataLayout{resident: []byte("hola"), size: 4}, &out); err != nil {
		t.Fatal(err)
	}
	if out.String() != "hola" {
		t.Fatalf("out = %q", out.String())
	}
}

func TestCopyDataDetectsShortRuns(t *testing.T) {
	vol := &memVolume{data: make([]byte, 512*8), cluster: 512}
	layout := dataLayout{extents: []ntfs.Extent{{StartLCN: 1, Length: 1}}, size: 512 * 3}
	if err := copyData(vol, layout, &bytes.Buffer{}); err == nil {
		t.Fatal("esperaba error: los runs cubren menos que el tamaño")
	}
}
