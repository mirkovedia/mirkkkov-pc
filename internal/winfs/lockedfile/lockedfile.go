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
// La parte pura (parseo del atributo y recorrido de extents) vive en este
// archivo y se testea con imágenes sintéticas; el acceso real al disco está en
// lockedfile_windows.go.
package lockedfile

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"github.com/mirkovedia/mirkkkov-pc/internal/winfs/ntfs"
)

// Errores que hacen que el llamador degrade a otro camino (VSS) en vez de
// fallar: no son corrupción, son casos que este lector no cubre.
var (
	ErrUnsupportedLayout = errors.New("el archivo usa un layout NTFS no soportado (comprimido, sparse, cifrado o con lista de atributos)")
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
)

// dataLayout describe dónde vive el contenido del $DATA sin nombre de un
// archivo: en el propio registro (residente) o en clústers del volumen.
type dataLayout struct {
	resident []byte
	extents  []ntfs.Extent
	size     uint64 // tamaño lógico real; el último clúster puede sobrar
}

// parseDataLayout recorre los atributos de un registro FILE (con fixup ya
// aplicado) y devuelve el layout del $DATA sin nombre.
func parseDataLayout(record []byte) (dataLayout, error) {
	if len(record) < 0x18 || string(record[0:4]) != "FILE" {
		return dataLayout{}, errors.New("registro sin firma FILE")
	}
	off := int(binary.LittleEndian.Uint16(record[0x14:0x16]))
	sawAttrList := false
	for off+0x18 <= len(record) {
		attrType := binary.LittleEndian.Uint32(record[off : off+4])
		if attrType == attrTerminator {
			break
		}
		attrLen := int(binary.LittleEndian.Uint32(record[off+4 : off+8]))
		if attrLen < 0x18 || off+attrLen > len(record) {
			return dataLayout{}, errors.New("longitud de atributo inválida")
		}
		nameLen := int(record[off+9])
		switch {
		case attrType == attrAttributeList:
			sawAttrList = true
		case attrType == attrData && nameLen == 0:
			return parseDataAttr(record[off : off+attrLen])
		}
		off += attrLen
	}
	if sawAttrList {
		// El $DATA puede vivir en un registro de extensión: seguir la lista
		// de atributos es trabajo para otra fase. Se avisa para que el
		// llamador use VSS.
		return dataLayout{}, fmt.Errorf("%w: lista de atributos", ErrUnsupportedLayout)
	}
	return dataLayout{}, ErrNoData
}

// parseDataAttr decodifica un atributo $DATA ya delimitado.
func parseDataAttr(attr []byte) (dataLayout, error) {
	flags := binary.LittleEndian.Uint16(attr[0x0C:0x0E])
	if flags&(attrFlagCompressed|attrFlagEncrypted|attrFlagSparse) != 0 {
		return dataLayout{}, fmt.Errorf("%w: flags 0x%04x", ErrUnsupportedLayout, flags)
	}
	if attr[8] == 0 { // residente
		valueLen := int(binary.LittleEndian.Uint32(attr[0x10:0x14]))
		valueOff := int(binary.LittleEndian.Uint16(attr[0x14:0x16]))
		if valueOff+valueLen > len(attr) {
			return dataLayout{}, errors.New("valor residente fuera del atributo")
		}
		content := make([]byte, valueLen)
		copy(content, attr[valueOff:valueOff+valueLen])
		return dataLayout{resident: content, size: uint64(valueLen)}, nil
	}
	if len(attr) < 0x40 {
		return dataLayout{}, errors.New("atributo no residente truncado")
	}
	runOff := int(binary.LittleEndian.Uint16(attr[0x20:0x22]))
	realSize := binary.LittleEndian.Uint64(attr[0x30:0x38])
	if runOff < 0x40 || runOff > len(attr) {
		return dataLayout{}, errors.New("offset de data runs fuera de rango")
	}
	extents, err := ntfs.DecodeDataRuns(attr[runOff:])
	if err != nil {
		return dataLayout{}, err
	}
	if len(extents) == 0 && realSize > 0 {
		return dataLayout{}, errors.New("atributo no residente sin data runs")
	}
	return dataLayout{extents: extents, size: realSize}, nil
}

// volume es lo mínimo que el recorrido de extents necesita del disco. Se
// abstrae para poder testearlo sobre una imagen en memoria.
type volume interface {
	ReadAt(offset int64, buf []byte) error
	ClusterSize() int
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
	buf := make([]byte, cluster*chunkClusters)
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
