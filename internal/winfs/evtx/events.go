package evtx

import (
	"strconv"
	"time"

	"github.com/mirkovedia/mirkkkov-pc/internal/winfs/wintext"
	"github.com/mirkovedia/mirkkkov-pc/internal/winfs/wintime"
)

// fieldSpec describe qué nombre y cómo interpretar cada substitution por
// posición (índice en subs, donde subs[0] es el EventID).
type fieldSpec struct {
	index int
	name  string
}

var eventFields = map[uint16][]fieldSpec{
	4624: {{1, "TargetUserName"}, {2, "LogonType"}},
	4634: {{1, "TargetUserName"}},
	1102: {{1, "SubjectUserName"}},
	104:  {{1, "Channel"}, {2, "SubjectUserName"}},
	7045: {{1, "ServiceName"}, {2, "ImagePath"}},
	106:  {{1, "TaskName"}},
	140:  {{1, "TaskName"}},
	141:  {{1, "TaskName"}},
}

// fieldsFor traduce las substitutions posicionales a un mapa nombre->valor
// según el EventID. Un índice fuera de rango se omite sin fallar.
func fieldsFor(eventID uint16, subs []SubValue) map[string]string {
	specs, ok := eventFields[eventID]
	if !ok {
		return map[string]string{}
	}
	out := make(map[string]string, len(specs))
	for _, s := range specs {
		if s.index >= len(subs) {
			continue
		}
		out[s.name] = renderValue(subs[s.index])
	}
	return out
}

// renderValue convierte un SubValue a string legible según su tipo.
func renderValue(v SubValue) string {
	switch v.Type {
	case TypeString:
		return wintext.DecodeUTF16(v.Raw)
	case TypeUInt16:
		if len(v.Raw) >= 2 {
			return strconv.FormatUint(uint64(v.Raw[0])|uint64(v.Raw[1])<<8, 10)
		}
	case TypeUInt32:
		if len(v.Raw) >= 4 {
			return strconv.FormatUint(uint64(readU32(v.Raw, 0)), 10)
		}
	case TypeFileTime:
		if len(v.Raw) >= 8 {
			ft := uint64(readU32(v.Raw, 0)) | uint64(readU32(v.Raw, 4))<<32
			return wintime.FiletimeToTime(ft).UTC().Format(time.RFC3339Nano)
		}
	}
	return ""
}

// StringValues devuelve, en orden, las substitutions de tipo string de un
// record. Sirve para los eventos cuyo mapeo posicional no está verificado
// contra un log real: el colector busca lo que necesita (una ruta de
// proceso, un usuario) entre todas en vez de apostar a un índice.
func (r Record) StringValues() []string {
	var out []string
	for _, s := range r.Subs {
		if s.Type == TypeString {
			if v := wintext.DecodeUTF16(s.Raw); v != "" {
				out = append(out, v)
			}
		}
	}
	return out
}

// TimeValues devuelve, en orden, las substitutions FILETIME de un record.
func (r Record) TimeValues() []time.Time {
	var out []time.Time
	for _, s := range r.Subs {
		if s.Type == TypeFileTime && len(s.Raw) >= 8 {
			ft := uint64(readU32(s.Raw, 0)) | uint64(readU32(s.Raw, 4))<<32
			out = append(out, wintime.FiletimeToTime(ft).UTC())
		}
	}
	return out
}
