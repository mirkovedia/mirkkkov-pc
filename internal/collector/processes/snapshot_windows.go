//go:build windows

package processes

import (
	"fmt"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// snapshot enumera los procesos con Toolhelp32 y completa ruta y hora de
// inicio abriendo cada uno con el mínimo acceso posible. Los procesos
// protegidos (antimalware, System) no se pueden abrir: quedan con nombre y
// sin ruta, que el motor trata como firma desconocida.
func snapshot() ([]Process, error) {
	h, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return nil, fmt.Errorf("CreateToolhelp32Snapshot: %w", err)
	}
	defer windows.CloseHandle(h)

	var entry windows.ProcessEntry32
	entry.Size = uint32(unsafe.Sizeof(entry))
	if err := windows.Process32First(h, &entry); err != nil {
		return nil, fmt.Errorf("Process32First: %w", err)
	}
	var out []Process
	for {
		if entry.ProcessID != 0 && entry.ProcessID != 4 {
			p := Process{
				PID:  entry.ProcessID,
				PPID: entry.ParentProcessID,
				Name: windows.UTF16ToString(entry.ExeFile[:]),
			}
			p.Path, p.Time = queryProcess(entry.ProcessID)
			out = append(out, p)
		}
		if err := windows.Process32Next(h, &entry); err != nil {
			break // ERROR_NO_MORE_FILES marca el fin
		}
	}
	return out, nil
}

// queryProcess devuelve la ruta de la imagen y la hora de creación, o
// valores vacíos si el proceso no se puede abrir.
func queryProcess(pid uint32) (string, time.Time) {
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return "", time.Time{}
	}
	defer windows.CloseHandle(h)

	var path string
	buf := make([]uint16, windows.MAX_LONG_PATH)
	size := uint32(len(buf))
	if err := windows.QueryFullProcessImageName(h, 0, &buf[0], &size); err == nil {
		path = windows.UTF16ToString(buf[:size])
	}
	var created, exit, kernel, user windows.Filetime
	var started time.Time
	if err := windows.GetProcessTimes(h, &created, &exit, &kernel, &user); err == nil {
		started = time.Unix(0, created.Nanoseconds()).UTC()
	}
	return path, started
}
