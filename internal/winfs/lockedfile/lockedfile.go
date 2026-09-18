// Package lockedfile lee archivos que otro proceso tiene abiertos en
// exclusiva, como los hives del registro en uso, por acceso raw al volumen
// NTFS: se localiza el registro MFT del archivo, se decodifica su atributo
// $DATA y se leen los clústers directamente del disco.
//
// Reemplaza al snapshot VSS como camino principal. VSS dependía de wmic (que
// Windows 11 24H2 ya no trae), tardaba varios segundos en crear el snapshot y
// dejaba shadow copies huérfanas si el proceso moría a mitad del escaneo. La
// lectura raw no crea nada que haya que limpiar.
//
// La parte pura (parseo de atributos y recorrido de extents) vive en este
// archivo y se testea con imágenes sintéticas; el acceso real al disco está en
// lockedfile_windows.go.
package lockedfile

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"sort"

	"github.com/mirkovedia/mirkkkov-pc/internal/winfs/ntfs"
)

// Errores que hacen que el llamador degrade a otro camino (VSS) en vez de
// fallar: no son corrupción, son casos que este lector no cubre.
var (
	ErrUnsupportedLayout = errors.New("el archivo usa un layout NTFS no soportado (comprimido, sparse o cifrado)")
	ErrNoData            = errors.New("el registro MFT no tiene atributo $DATA")
)

// Tipos y flags de atributo (ntfs.h).
const (
	attrAttributeList = 0x20
	attrData          = 0x80
	attrTerminator    = 0xFFFFFFFF

	attrFlagCompressed = 0x0001
	attrFlagEncrypted  = 0x4000
	attrFlagSparse     = 0x8000

	// maxAttrListBytes acota la lista de atributos no residente: una lista
	// real mide pocos KB; más que esto es un registro corrupto.
	maxAttrListBytes = 1 << 20
)

// dataLayout describe dónde vive el contenido del $DATA sin nombre de un
// archivo: en el propio registro (residente) o en clústers del volumen.
type dataLayout struct {
	resident []byte
	extents  []ntfs.Extent
	size     uint64 // tamaño lógico real; el último clúster puede sobrar
}

// piece es un tramo del $DATA. Un archivo chico o poco fragmentado tiene uno
// solo; uno grande y fragmentado (el hive SOFTWARE) reparte sus data runs en
// varios registros MFT de extensión, cada uno con su tramo.
type piece struct {
	startVCN uint64
	layout   dataLayout
}

// volume es lo mínimo que el recorrido de extents necesita del disco. Se
// abstrae para poder testearlo sobre una imagen en memoria.
type volume interface {
	ReadAt(offset int64, buf []byte) error
	ClusterSize() int
}

// recordSource entrega registros MFT por file reference, con el fixup ya
// resuelto. Hace falta para seguir una lista de atributos.
type recordSource interface {
	FileRecord(ref uint64) ([]byte, error)
}

// walkAttrs recorre los atributos de un registro FILE.
func walkAttrs(record []byte, fn func(attrType uint32, attr []byte) error) error {
	if len(record) < 0x18 || string(record[0:4]) != "FILE" {
		return errors.New("registro sin firma FILE")
	}
	off := int(binary.LittleEndian.Uint16(record[0x14:0x16]))
	for off+0x18 <= len(record) {
		attrType := binary.LittleEndian.Uint32(record[off : off+4])
		if attrType == attrTerminator {
			return nil
		}
		attrLen := int(binary.LittleEndian.Uint32(record[off+4 : off+8]))
		if attrLen < 0x18 || off+attrLen > len(record) {
			return errors.New("longitud de atributo inválida")
		}
		if err := fn(attrType, record[off:off+attrLen]); err != nil {
			return err
		}
		off += attrLen
	}
	return nil
}

// scanRecord devuelve los tramos de $DATA sin nombre de un registro y, si lo
// tiene, su atributo $ATTRIBUTE_LIST crudo.
func scanRecord(record []byte) (pieces []piece, attrList []byte, err error) {
	err = walkAttrs(record, func(attrType uint32, attr []byte) error {
		switch {
		case attrType == attrAttributeList:
			attrList = attr
		case attrType == attrData && attr[9] == 0: // nameLen == 0: el $DATA principal
			p, err := parseDataAttr(attr)
			if err != nil {
				return err
			}
			pieces = append(pieces, p)
		}
		return nil
	})
	return pieces, attrList, err
}

// parseDataLayout resuelve el layout de un registro que NO usa lista de
// atributos. Se conserva para los llamadores y tests que solo tienen el
// registro base; resolveLayout es el camino completo.
func parseDataLayout(record []byte) (dataLayout, error) {
	pieces, attrList, err := scanRecord(record)
	if err != nil {
		return dataLayout{}, err
	}
	if attrList != nil {
		return dataLayout{}, errors.New("el registro usa lista de atributos: hace falta resolveLayout")
	}
	return mergePieces(pieces)
}

// resolveLayout resuelve el layout completo, siguiendo la lista de atributos
// a los registros de extensión cuando el archivo la usa.
func resolveLayout(src recordSource, vol volume, record []byte) (dataLayout, error) {
	pieces, attrList, err := scanRecord(record)
	if err != nil {
		return dataLayout{}, err
	}
	if attrList == nil {
		return mergePieces(pieces)
	}

	content, err := attrContent(vol, attrList)
	if err != nil {
		return dataLayout{}, fmt.Errorf("leer la lista de atributos: %w", err)
	}
	refs := dataRecordRefs(content)
	if len(refs) == 0 {
		return dataLayout{}, ErrNoData
	}
	// La lista manda: aunque el registro base tenga un tramo, se vuelve a
	// pedir por su referencia junto con los de extensión, así el orden y los
	// duplicados se resuelven en un solo lugar.
	pieces = pieces[:0]
	for _, ref := range refs {
		rec, err := src.FileRecord(ref)
		if err != nil {
			return dataLayout{}, fmt.Errorf("registro de extensión %d: %w", ref&0x0000FFFFFFFFFFFF, err)
		}
		more, _, err := scanRecord(rec)
		if err != nil {
			return dataLayout{}, err
		}
		pieces = append(pieces, more...)
	}
	return mergePieces(pieces)
}

// mergePieces ordena los tramos por VCN y concatena sus extents. El tamaño
// real solo es válido en el tramo que arranca en el VCN 0.
func mergePieces(pieces []piece) (dataLayout, error) {
	if len(pieces) == 0 {
		return dataLayout{}, ErrNoData
	}
	sort.SliceStable(pieces, func(i, j int) bool { return pieces[i].startVCN < pieces[j].startVCN })
	first := pieces[0]
	if first.startVCN != 0 {
		return dataLayout{}, errors.New("falta el primer tramo del $DATA (VCN 0)")
	}
	if first.layout.resident != nil {
		return first.layout, nil
	}
	out := dataLayout{size: first.layout.size}
	var lastVCN uint64
	for i, p := range pieces {
		if p.layout.resident != nil {
			return dataLayout{}, errors.New("tramo residente en un $DATA repartido")
		}
		if i > 0 && p.startVCN < lastVCN {
			continue // tramo repetido (el base listado dos veces)
		}
		out.extents = append(out.extents, p.layout.extents...)
		for _, e := range p.layout.extents {
			lastVCN += e.Length
		}
	}
	if len(out.extents) == 0 && out.size > 0 {
		return dataLayout{}, errors.New("atributo no residente sin data runs")
	}
	return out, nil
}

// parseDataAttr decodifica un atributo $DATA ya delimitado.
func parseDataAttr(attr []byte) (piece, error) {
	flags := binary.LittleEndian.Uint16(attr[0x0C:0x0E])
	if flags&(attrFlagCompressed|attrFlagEncrypted|attrFlagSparse) != 0 {
		return piece{}, fmt.Errorf("%w: flags 0x%04x", ErrUnsupportedLayout, flags)
	}
	if attr[8] == 0 { // residente
		content, err := residentContent(attr)
		if err != nil {
			return piece{}, err
		}
		return piece{layout: dataLayout{resident: content, size: uint64(len(content))}}, nil
	}
	if len(attr) < 0x40 {
		return piece{}, errors.New("atributo no residente truncado")
	}
	startVCN := binary.LittleEndian.Uint64(attr[0x10:0x18])
	runOff := int(binary.LittleEndian.Uint16(attr[0x20:0x22]))
	realSize := binary.LittleEndian.Uint64(attr[0x30:0x38])
	if runOff < 0x40 || runOff > len(attr) {
		return piece{}, errors.New("offset de data runs fuera de rango")
	}
	extents, err := ntfs.DecodeDataRuns(attr[runOff:])
	if err != nil {
		return piece{}, err
	}
	return piece{startVCN: startVCN, layout: dataLayout{extents: extents, size: realSize}}, nil
}

func residentContent(attr []byte) ([]byte, error) {
	valueLen := int(binary.LittleEndian.Uint32(attr[0x10:0x14]))
	valueOff := int(binary.LittleEndian.Uint16(attr[0x14:0x16]))
	if valueOff+valueLen > len(attr) {
		return nil, errors.New("valor residente fuera del atributo")
	}
	content := make([]byte, valueLen)
	copy(content, attr[valueOff:valueOff+valueLen])
	return content, nil
}

// attrContent devuelve el contenido de un atributo cualquiera: del propio
// registro si es residente, o leyéndolo del volumen si no lo es.
func attrContent(vol volume, attr []byte) ([]byte, error) {
	if attr[8] == 0 {
		return residentContent(attr)
	}
	p, err := parseDataAttr(attr) // mismo encabezado no residente que $DATA
	if err != nil {
		return nil, err
	}
	if p.layout.size > maxAttrListBytes {
		return nil, fmt.Errorf("lista de atributos de %d bytes: registro corrupto", p.layout.size)
	}
	var buf bytes.Buffer
	if err := copyData(vol, p.layout, &buf); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// dataRecordRefs recorre una lista de atributos y devuelve, en orden de VCN y
// sin repetir, las referencias de los registros que guardan un tramo del
// $DATA sin nombre.
//
// Entrada de la lista: tipo(4) longitud(2) largoNombre(1) offNombre(1)
// VCNinicial(8) referenciaBase(8) id(2) nombre…
func dataRecordRefs(list []byte) []uint64 {
	type entry struct {
		vcn uint64
		ref uint64
	}
	var entries []entry
	for off := 0; off+0x1A <= len(list); {
		entryLen := int(binary.LittleEndian.Uint16(list[off+4 : off+6]))
		if entryLen < 0x1A || off+entryLen > len(list) {
			break
		}
		attrType := binary.LittleEndian.Uint32(list[off : off+4])
		nameLen := list[off+6]
		if attrType == attrData && nameLen == 0 {
			entries = append(entries, entry{
				vcn: binary.LittleEndian.Uint64(list[off+8 : off+16]),
				ref: binary.LittleEndian.Uint64(list[off+16 : off+24]),
			})
		}
		off += entryLen
	}
	sort.SliceStable(entries, func(i, j int) bool { return entries[i].vcn < entries[j].vcn })
	seen := make(map[uint64]bool)
	var refs []uint64
	for _, e := range entries {
		if !seen[e.ref] {
			seen[e.ref] = true
			refs = append(refs, e.ref)
		}
	}
	return refs
}

// chunkClusters acota cada lectura: 1 MB con clústers de 4 KB. Los hives
// grandes (SOFTWARE ronda los 100 MB) se copian en streaming, sin cargarlos
// enteros en memoria.
const chunkClusters = 256

// copyData escribe en w el contenido descrito por layout, leyendo del
// volumen de a bloques alineados a clúster y cortando en el tamaño real.
func copyData(vol volume, layout dataLayout, w io.Writer) error {
	if layout.resident != nil {
		_, err := w.Write(layout.resident[:layout.size])
		return err
	}
	cluster := int64(vol.ClusterSize())
	if cluster <= 0 {
		return errors.New("tamaño de clúster inválido")
	}
	remaining := int64(layout.size)
	// Alineado: vol es un volumen abierto en crudo y Windows rechaza los
	// buffers que no estén alineados al sector físico.
	buf := ntfs.AlignedBuffer(int(cluster * chunkClusters))
	for _, ext := range layout.extents {
		extBytes := int64(ext.Length) * cluster
		diskOff := int64(ext.StartLCN) * cluster
		for pos := int64(0); pos < extBytes && remaining > 0; {
			toRead := int64(len(buf))
			if rem := extBytes - pos; rem < toRead {
				toRead = rem
			}
			if err := vol.ReadAt(diskOff+pos, buf[:toRead]); err != nil {
				return fmt.Errorf("leer clústers en offset %d: %w", diskOff+pos, err)
			}
			toWrite := toRead
			if toWrite > remaining {
				toWrite = remaining
			}
			if _, err := w.Write(buf[:toWrite]); err != nil {
				return err
			}
			pos += toRead
			remaining -= toWrite
		}
	}
	if remaining > 0 {
		return fmt.Errorf("los data runs cubren menos que el tamaño del archivo: faltan %d bytes", remaining)
	}
	return nil
}
