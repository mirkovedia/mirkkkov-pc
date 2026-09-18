package lockedfile

import (
	"bytes"
	"encoding/binary"
	"errors"
	"testing"

	"github.com/mirkovedia/mirkkkov-pc/internal/winfs/ntfs"
)

// El hive SOFTWARE de una máquina real es grande y está fragmentado: sus data
// runs no entran en un registro MFT, así que NTFS los reparte en registros de
// extensión y deja en el base un $ATTRIBUTE_LIST que dice dónde está cada
// tramo. El primer escaneo real sobre un runner falló exactamente ahí.

const testCluster = 512

// listEntry arma una entrada de $ATTRIBUTE_LIST (0x20 bytes, sin nombre).
func listEntry(attrType uint32, nameLen byte, vcn, ref uint64) []byte {
	e := make([]byte, 0x20)
	binary.LittleEndian.PutUint32(e[0:4], attrType)
	binary.LittleEndian.PutUint16(e[4:6], 0x20)
	e[6] = nameLen
	e[7] = 0x1A
	binary.LittleEndian.PutUint64(e[8:16], vcn)
	binary.LittleEndian.PutUint64(e[16:24], ref)
	return e
}

// residentAttr arma un atributo residente de cualquier tipo.
func residentAttr(attrType uint32, content []byte) []byte {
	a := residentData(content)
	binary.LittleEndian.PutUint32(a[0:4], attrType)
	return a
}

// dataPiece arma un tramo no residente de $DATA que arranca en startVCN.
func dataPiece(startVCN uint64, runs []byte, realSize uint64) []byte {
	a := nonResidentData(runs, realSize, 0)
	binary.LittleEndian.PutUint64(a[0x10:0x18], startVCN)
	return a
}

// namedStream arma un $DATA con nombre (un ADS), que no es el contenido del
// archivo y tiene que ignorarse.
func namedStream(runs []byte, realSize uint64) []byte {
	a := nonResidentData(runs, realSize, 0)
	a[9] = 4 // nameLen en caracteres
	return a
}

// memSource entrega registros por referencia.
type memSource map[uint64][]byte

func (m memSource) FileRecord(ref uint64) ([]byte, error) {
	rec, ok := m[ref]
	if !ok {
		return nil, errors.New("registro inexistente")
	}
	return rec, nil
}

// fillClusters pinta un rango de clústers de la imagen con un byte.
func fillClusters(vol *memVolume, lcn, count int, b byte) {
	for i := lcn * vol.cluster; i < (lcn+count)*vol.cluster; i++ {
		vol.data[i] = b
	}
}

func newTestVolume() *memVolume {
	return &memVolume{data: make([]byte, testCluster*64), cluster: testCluster}
}

const (
	refBase = uint64(1)<<48 | 50
	refExtA = uint64(3)<<48 | 100
	refExtB = uint64(7)<<48 | 101
)

// fragmentedFile arma un archivo cuyo $DATA vive en dos registros de
// extensión: 3 clústers 'A' en el LCN 10 y 2 clústers 'B' en el LCN 20.
func fragmentedFile(vol *memVolume, list []byte) (memSource, []byte, uint64) {
	fillClusters(vol, 10, 3, 'A')
	fillClusters(vol, 20, 2, 'B')
	size := uint64(testCluster*5 - 100)
	src := memSource{
		refExtA: record(dataPiece(0, []byte{0x11, 0x03, 0x0A, 0x00}, size)),
		refExtB: record(dataPiece(3, []byte{0x11, 0x02, 0x14, 0x00}, 0)),
	}
	base := record(residentAttr(attrAttributeList, list))
	src[refBase] = base
	return src, base, size
}

func assertFragmentedContent(t *testing.T, vol *memVolume, layout dataLayout, size uint64) {
	t.Helper()
	var out bytes.Buffer
	if err := copyData(vol, layout, &out); err != nil {
		t.Fatal(err)
	}
	got := out.Bytes()
	if uint64(len(got)) != size {
		t.Fatalf("len = %d, want %d", len(got), size)
	}
	if got[0] != 'A' || got[3*testCluster-1] != 'A' || got[3*testCluster] != 'B' || got[len(got)-1] != 'B' {
		t.Fatal("el contenido no sigue el orden de los tramos")
	}
}

func TestResolveLayoutFollowsAttributeList(t *testing.T) {
	vol := newTestVolume()
	list := append(listEntry(0x10, 0, 0, refBase), // $STANDARD_INFORMATION: se ignora
		append(listEntry(attrData, 0, 0, refExtA), listEntry(attrData, 0, 3, refExtB)...)...)
	src, base, size := fragmentedFile(vol, list)

	layout, err := resolveLayout(src, vol, base)
	if err != nil {
		t.Fatal(err)
	}
	want := []ntfs.Extent{{StartLCN: 10, Length: 3}, {StartLCN: 20, Length: 2}}
	if len(layout.extents) != 2 || layout.extents[0] != want[0] || layout.extents[1] != want[1] || layout.size != size {
		t.Fatalf("layout = %+v", layout)
	}
	assertFragmentedContent(t, vol, layout, size)
}

func TestResolveLayoutSortsPiecesByVCN(t *testing.T) {
	vol := newTestVolume()
	// La lista trae el segundo tramo antes que el primero.
	list := append(listEntry(attrData, 0, 3, refExtB), listEntry(attrData, 0, 0, refExtA)...)
	src, base, size := fragmentedFile(vol, list)
	layout, err := resolveLayout(src, vol, base)
	if err != nil {
		t.Fatal(err)
	}
	assertFragmentedContent(t, vol, layout, size)
}

func TestResolveLayoutIgnoresNamedStreams(t *testing.T) {
	vol := newTestVolume()
	list := append(listEntry(attrData, 4, 0, refExtB), // ADS con nombre: no es el contenido
		append(listEntry(attrData, 0, 0, refExtA), listEntry(attrData, 0, 3, refExtB)...)...)
	src, base, size := fragmentedFile(vol, list)
	// El registro B trae además el stream con nombre.
	src[refExtB] = record(namedStream([]byte{0x11, 0x01, 0x28, 0x00}, 99),
		dataPiece(3, []byte{0x11, 0x02, 0x14, 0x00}, 0))
	layout, err := resolveLayout(src, vol, base)
	if err != nil {
		t.Fatal(err)
	}
	assertFragmentedContent(t, vol, layout, size)
}

// TestResolveLayoutBasePieceListedTwice: el primer tramo suele quedar en el
// propio registro base, que la lista referencia. No tiene que duplicarse.
func TestResolveLayoutBasePieceListedTwice(t *testing.T) {
	vol := newTestVolume()
	fillClusters(vol, 10, 3, 'A')
	fillClusters(vol, 20, 2, 'B')
	size := uint64(testCluster*5 - 100)
	list := append(listEntry(attrData, 0, 0, refBase), listEntry(attrData, 0, 3, refExtB)...)
	base := record(residentAttr(attrAttributeList, list), dataPiece(0, []byte{0x11, 0x03, 0x0A, 0x00}, size))
	src := memSource{refBase: base, refExtB: record(dataPiece(3, []byte{0x11, 0x02, 0x14, 0x00}, 0))}
	layout, err := resolveLayout(src, vol, base)
	if err != nil {
		t.Fatal(err)
	}
	assertFragmentedContent(t, vol, layout, size)
}

func TestResolveLayoutNonResidentAttributeList(t *testing.T) {
	vol := newTestVolume()
	list := append(listEntry(attrData, 0, 0, refExtA), listEntry(attrData, 0, 3, refExtB)...)
	src, _, size := fragmentedFile(vol, list)
	// La lista misma vive en el clúster 30.
	copy(vol.data[30*testCluster:], list)
	listAttr := nonResidentData([]byte{0x11, 0x01, 0x1E, 0x00}, uint64(len(list)), 0)
	binary.LittleEndian.PutUint32(listAttr[0:4], attrAttributeList)
	base := record(listAttr)

	layout, err := resolveLayout(src, vol, base)
	if err != nil {
		t.Fatal(err)
	}
	assertFragmentedContent(t, vol, layout, size)
}

func TestResolveLayoutMissingFirstPiece(t *testing.T) {
	vol := newTestVolume()
	list := listEntry(attrData, 0, 3, refExtB)
	src, base, _ := fragmentedFile(vol, list)
	if _, err := resolveLayout(src, vol, base); err == nil {
		t.Fatal("sin el tramo del VCN 0 no se puede reconstruir el archivo")
	}
}

func TestResolveLayoutMissingExtensionRecord(t *testing.T) {
	vol := newTestVolume()
	list := append(listEntry(attrData, 0, 0, refExtA), listEntry(attrData, 0, 3, refExtB)...)
	src, base, _ := fragmentedFile(vol, list)
	delete(src, refExtB)
	if _, err := resolveLayout(src, vol, base); err == nil {
		t.Fatal("un registro de extensión inaccesible tiene que ser un error, no un archivo truncado")
	}
}

func TestResolveLayoutWithoutListBehavesAsBefore(t *testing.T) {
	vol := newTestVolume()
	base := record(residentData([]byte("regf chico")))
	layout, err := resolveLayout(memSource{}, vol, base)
	if err != nil {
		t.Fatal(err)
	}
	if string(layout.resident) != "regf chico" {
		t.Fatalf("layout = %+v", layout)
	}
}
