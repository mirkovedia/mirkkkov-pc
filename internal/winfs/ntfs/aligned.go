// internal/winfs/ntfs/aligned.go
package ntfs

import "unsafe"

// RawIOAlign es la alineación que se le da a todo buffer y a toda longitud de
// lectura sobre un volumen abierto en crudo. 4096 cubre los discos de sector
// físico de 4 KB (512e y 4Kn), que hoy son casi todos.
const RawIOAlign = 4096

// AlignedBuffer devuelve un buffer de size bytes cuya dirección de memoria es
// múltiplo de RawIOAlign.
//
// Las lecturas sobre un volumen abierto en crudo son sin caché, y Windows
// exige para ellas que el buffer esté alineado al sector del disco. Un
// make([]byte, 512) de Go queda alineado a 512 por cómo el runtime reparte
// sus clases de tamaño, que alcanza en un disco 512 nativo y falla con
// ERROR_INVALID_PARAMETER ("The parameter is incorrect") en uno con sector
// físico de 4 KB. Así falló deleted_entries en el primer escaneo real sobre
// un runner de CI.
func AlignedBuffer(size int) []byte {
	buf := make([]byte, size+RawIOAlign)
	off := int(uintptr(unsafe.Pointer(&buf[0])) & (RawIOAlign - 1))
	if off != 0 {
		off = RawIOAlign - off
	}
	return buf[off : off+size : off+size]
}

// RoundUpToAlign redondea n hacia arriba al múltiplo de RawIOAlign: en un
// disco 4Kn la LONGITUD de la lectura también tiene que ser múltiplo del
// sector.
func RoundUpToAlign(n int) int {
	return (n + RawIOAlign - 1) / RawIOAlign * RawIOAlign
}
