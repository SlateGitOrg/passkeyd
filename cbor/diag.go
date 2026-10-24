package cbor

import (
	"encoding/hex"
	"math"
	"math/big"
	"strconv"
	"strings"
)

// Diagnostic renders v in the diagnostic notation of RFC 8949 section 8,
// e.g. {1: 2, "a": [h'01', true]}. Indefinite-length strings are shown with
// their chunks concatenated; indefinite arrays and maps are prefixed with
// "_ " as in the RFC.
func Diagnostic(v Value) string {
	var b strings.Builder
	diag(&b, v)
	return b.String()
}

func diag(b *strings.Builder, v Value) {
	switch v.kind {
	case KindUint:
		b.WriteString(strconv.FormatUint(v.arg, 10))
	case KindNegInt:
		n := new(big.Int).SetUint64(v.arg)
		n.Neg(n).Sub(n, big.NewInt(1))
		b.WriteString(n.String())
	case KindBytes:
		b.WriteString("h'")
		b.WriteString(hex.EncodeToString(v.data))
		b.WriteByte('\'')
	case KindText:
		b.WriteString(strconv.Quote(string(v.data)))
	case KindArray:
		b.WriteByte('[')
		if v.indefinite {
			b.WriteString("_ ")
		}
		for i, it := range v.items {
			if i > 0 {
				b.WriteString(", ")
			}
			diag(b, it)
		}
		b.WriteByte(']')
	case KindMap:
		b.WriteByte('{')
		if v.indefinite {
			b.WriteString("_ ")
		}
		for i, p := range v.pairs {
			if i > 0 {
				b.WriteString(", ")
			}
			diag(b, p.Key)
			b.WriteString(": ")
			diag(b, p.Value)
		}
		b.WriteByte('}')
	case KindTag:
		b.WriteString(strconv.FormatUint(v.arg, 10))
		b.WriteByte('(')
		if len(v.items) == 1 {
			diag(b, v.items[0])
		}
		b.WriteByte(')')
	case KindSimple:
		switch v.arg {
		case SimpleFalse:
			b.WriteString("false")
		case SimpleTrue:
			b.WriteString("true")
		case SimpleNull:
			b.WriteString("null")
		case SimpleUndefined:
			b.WriteString("undefined")
		default:
			b.WriteString("simple(" + strconv.FormatUint(v.arg, 10) + ")")
		}
	case KindFloat:
		b.WriteString(formatFloat(v.f))
	default:
		b.WriteString("<invalid>")
	}
}

func formatFloat(f float64) string {
	switch {
	case math.IsNaN(f):
		return "NaN"
	case math.IsInf(f, 1):
		return "Infinity"
	case math.IsInf(f, -1):
		return "-Infinity"
	}
	abs := math.Abs(f)
	if abs != 0 && (abs >= 1e21 || abs < 1e-6) {
		return strconv.FormatFloat(f, 'g', -1, 64)
	}
	s := strconv.FormatFloat(f, 'f', -1, 64)
	if !strings.ContainsRune(s, '.') {
		s += ".0"
	}
	return s
}
