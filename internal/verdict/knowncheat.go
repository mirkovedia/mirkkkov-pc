// internal/verdict/knowncheat.go
package verdict

import (
	"bufio"
	"bytes"
	_ "embed"
	"io"
	"os"
	"strings"
	"sync"
)

// knownCheatHashes es la lista embebida de SHA-1 de cheats y loaders
// conocidos. Una línea por hash: "<sha1 en hex> <nombre o comentario>";
// las líneas vacías y las que empiezan con # se ignoran.
//
// Se distribuye VACÍA de hashes reales a propósito: cada entrada tiene que
// salir de una muestra verificada, no de una lista copiada de internet. La
// comunidad que opere el agente la completa con AddKnownCheats o con un
// cheats.txt junto al ejecutable.
//
//go:embed knowncheat_hashes.txt
var knownCheatHashes string

var (
	knownCheatsMu sync.RWMutex
	knownCheats   = parseKnownCheats(strings.NewReader(knownCheatHashes))
)

// parseKnownCheats lee el formato de lista y devuelve sha1 (minúsculas) → nombre.
func parseKnownCheats(r io.Reader) map[string]string {
	out := make(map[string]string)
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		hash := strings.ToLower(fields[0])
		if len(hash) != 40 || !isHex(hash) {
			continue
		}
		name := "cheat conocido"
		if len(fields) > 1 {
			name = strings.Join(fields[1:], " ")
		}
		out[hash] = name
	}
	return out
}

func isHex(s string) bool {
	for _, c := range s {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return false
		}
	}
	return true
}

// AddKnownCheats suma hashes a la lista en memoria a partir de un lector con
// el mismo formato que la lista embebida. Devuelve cuántos se agregaron.
func AddKnownCheats(r io.Reader) int {
	extra := parseKnownCheats(r)
	knownCheatsMu.Lock()
	defer knownCheatsMu.Unlock()
	for h, n := range extra {
		knownCheats[h] = n
	}
	return len(extra)
}

// LoadKnownCheatsFile carga un archivo de hashes si existe. Un archivo
// ausente no es error: es lo normal.
func LoadKnownCheatsFile(path string) (int, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return 0, nil
		}
		return 0, err
	}
	return AddKnownCheats(bytes.NewReader(data)), nil
}

// KnownCheat devuelve el nombre asociado a un SHA-1 si está en la lista.
func KnownCheat(sha1 string) (string, bool) {
	knownCheatsMu.RLock()
	defer knownCheatsMu.RUnlock()
	name, ok := knownCheats[strings.ToLower(strings.TrimSpace(sha1))]
	return name, ok
}

// KnownCheatCount devuelve cuántos hashes hay cargados.
func KnownCheatCount() int {
	knownCheatsMu.RLock()
	defer knownCheatsMu.RUnlock()
	return len(knownCheats)
}
