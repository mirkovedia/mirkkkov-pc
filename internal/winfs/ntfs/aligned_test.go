package ntfs

import (
	"testing"
	"unsafe"
)

func TestAlignedBufferIsAligned(t *testing.T) {
	// Varias asignaciones de tamaños chicos: son las que el runtime de Go NO
	// alinea a 4 KB por su cuenta.
	for _, size := range []int{512, 1024, 4096, 1 << 20} {
		for i := 0; i < 32; i++ {
			buf := AlignedBuffer(size)
			if len(buf) != size || cap(buf) != size {
				t.Fatalf("size %d: len=%d cap=%d", size, len(buf), cap(buf))
			}
			if addr := uintptr(unsafe.Pointer(&buf[0])); addr%RawIOAlign != 0 {
				t.Fatalf("size %d: dirección %#x no alineada a %d", size, addr, RawIOAlign)
			}
		}
	}
}

func TestRoundUpToAlign(t *testing.T) {
	cases := map[int]int{1: 4096, 512: 4096, 1024: 4096, 4096: 4096, 4097: 8192, 1 << 20: 1 << 20}
	for in, want := range cases {
		if got := RoundUpToAlign(in); got != want {
			t.Errorf("RoundUpToAlign(%d) = %d, want %d", in, got, want)
		}
	}
}
