package mft

import (
	"bytes"
	"testing"
)

// inMemoryForm devuelve el registro como lo entrega FSCTL_GET_NTFS_FILE_RECORD:
// con el fixup ya aplicado por NTFS.
func inMemoryForm(t *testing.T, disk []byte) []byte {
	t.Helper()
	fixed, err := ApplyFixup(disk)
	if err != nil {
		t.Fatal(err)
	}
	return fixed
}

// TestNormalizeFixupAcceptsBothForms: el mismo registro tiene que dar el
// mismo resultado venga del disco en crudo o de FSCTL.
func TestNormalizeFixupAcceptsBothForms(t *testing.T) {
	// Un $FILE_NAME largo empuja datos reales hasta el final del primer
	// sector, para que el fixup tenga algo distinto de cero que restaurar.
	fn := fnContent(ftKnown, ftKnown, ftKnown, ftKnown, 1, "un_nombre_de_archivo_bastante_largo_para_cruzar_el_sector.exe")
	disk := buildRecord(0x01, buildAttr(attrStandardInfo, siContent(ftKnown, ftKnown, ftKnown, ftKnown)),
		buildAttr(attrFileName, fn), buildAttr(attrFileName, fn), buildAttr(attrFileName, fn))
	memory := inMemoryForm(t, disk)
	if bytes.Equal(disk, memory) {
		t.Fatal("el fixture no distingue las dos formas")
	}

	fromDisk, err := NormalizeFixup(disk)
	if err != nil {
		t.Fatalf("forma de disco: %v", err)
	}
	fromMemory, err := NormalizeFixup(memory)
	if err != nil {
		t.Fatalf("forma de memoria (la de FSCTL): %v", err)
	}
	if !bytes.Equal(fromDisk, fromMemory) {
		t.Fatal("las dos formas deben normalizar al mismo registro")
	}
}

// TestParseRecordAcceptsFSCTLForm es la regresión del bug: ParseRecord
// rechazaba todo registro venido de FSCTL_GET_NTFS_FILE_RECORD y el colector
// de timestomping, que descarta lo que no parsea, nunca evaluó nada.
func TestParseRecordAcceptsFSCTLForm(t *testing.T) {
	disk := buildRecord(0x01,
		buildAttr(attrStandardInfo, siContent(ftKnown, ftKnown, ftKnown, ftKnown)),
		buildAttr(attrFileName, fnContent(ftKnown, ftKnown, ftKnown, ftKnown, 1, "cheat.exe")))
	rec, err := ParseRecord(inMemoryForm(t, disk))
	if err != nil {
		t.Fatalf("ParseRecord sobre la forma de FSCTL: %v", err)
	}
	if !rec.HasSI || !rec.HasFN || rec.FileName != "cheat.exe" {
		t.Fatalf("rec = %+v", rec)
	}
}

func TestNormalizeFixupStillRejectsCorruption(t *testing.T) {
	disk := buildRecord(0x01, buildAttr(attrStandardInfo, siContent(ftKnown, ftKnown, ftKnown, ftKnown)))
	// Un final de sector que no es ni el USN ni el valor guardado: escritura
	// a medias o edición a mano.
	disk[510], disk[511] = 0xAB, 0xCD
	if _, err := NormalizeFixup(disk); err == nil {
		t.Fatal("un final de sector inconsistente debe rechazarse")
	}
}
