package cbor

import (
	"bytes"
	"encoding/binary"
	"math"
	"slices"
)

// Encode returns the preferred serialization (RFC 8949 section 4.1) of v:
// shortest-form arguments, definite lengths, and the shortest float width
// that preserves the value. Map entries keep their order.
//
// Simple values 24..31 have no well-formed encoding; they are emitted as
// undefined so Encode never produces ill-formed output.
func Encode(v Value) []byte {
	var e encoder
	e.value(v)
	return e.buf.Bytes()
}

// EncodeCanonical is Encode with map keys sorted in CTAP2 canonical order
// (shorter encoded key first, then bytewise), recursively. Authenticators
// must emit this form, so the virtual authenticator uses it.
func EncodeCanonical(v Value) []byte {
	e := encoder{canonical: true}
	e.value(v)
	return e.buf.Bytes()
}

type encoder struct {
	buf       bytes.Buffer
	canonical bool
}

func (e *encoder) head(major byte, arg uint64) {
	m := major << 5
	switch {
	case arg < 24:
		e.buf.WriteByte(m | byte(arg))
	case arg <= math.MaxUint8:
		e.buf.Write([]byte{m | 24, byte(arg)})
	case arg <= math.MaxUint16:
		e.buf.WriteByte(m | 25)
		e.buf.Write(binary.BigEndian.AppendUint16(nil, uint16(arg)))
	case arg <= math.MaxUint32:
		e.buf.WriteByte(m | 26)
		e.buf.Write(binary.BigEndian.AppendUint32(nil, uint32(arg)))
	default:
		e.buf.WriteByte(m | 27)
		e.buf.Write(binary.BigEndian.AppendUint64(nil, arg))
	}
}

func (e *encoder) value(v Value) {
	switch v.kind {
	case KindUint:
		e.head(0, v.arg)
	case KindNegInt:
		e.head(1, v.arg)
	case KindBytes:
		e.head(2, uint64(len(v.data)))
		e.buf.Write(v.data)
	case KindText:
		e.head(3, uint64(len(v.data)))
		e.buf.Write(v.data)
	case KindArray:
		e.head(4, uint64(len(v.items)))
		for _, it := range v.items {
			e.value(it)
		}
	case KindMap:
		e.mapValue(v.pairs)
	case KindTag:
		e.head(6, v.arg)
		if len(v.items) == 1 {
			e.value(v.items[0])
		} else {
			e.value(Undefined())
		}
	case KindSimple:
		switch {
		case v.arg < 24:
			e.buf.WriteByte(0xe0 | byte(v.arg))
		case v.arg >= 32 && v.arg <= math.MaxUint8:
			e.buf.Write([]byte{0xf8, byte(v.arg)})
		default:
			e.buf.WriteByte(0xe0 | SimpleUndefined)
		}
	case KindFloat:
		e.float(v.f)
	default:
		e.buf.WriteByte(0xe0 | SimpleUndefined)
	}
}

func (e *encoder) mapValue(pairs []Pair) {
	e.head(5, uint64(len(pairs)))
	if !e.canonical {
		for _, p := range pairs {
			e.value(p.Key)
			e.value(p.Value)
		}
		return
	}
	type enc struct{ k, v []byte }
	encs := make([]enc, len(pairs))
	for i, p := range pairs {
		ke := encoder{canonical: true}
		ke.value(p.Key)
		ve := encoder{canonical: true}
		ve.value(p.Value)
		encs[i] = enc{ke.buf.Bytes(), ve.buf.Bytes()}
	}
	slices.SortStableFunc(encs, func(a, b enc) int { return canonicalCompare(a.k, b.k) })
	for _, x := range encs {
		e.buf.Write(x.k)
		e.buf.Write(x.v)
	}
}

// canonicalCompare orders encoded keys per CTAP2: shorter first, then
// bytewise. Because the initial byte carries the major type and the
// argument width, this also groups keys by major type.
func canonicalCompare(a, b []byte) int {
	if len(a) != len(b) {
		if len(a) < len(b) {
			return -1
		}
		return 1
	}
	return bytes.Compare(a, b)
}

func (e *encoder) float(f float64) {
	if math.IsNaN(f) {
		e.buf.Write([]byte{0xf9, 0x7e, 0x00})
		return
	}
	if h, ok := float64ToHalf(f); ok {
		e.buf.WriteByte(0xf9)
		e.buf.Write(binary.BigEndian.AppendUint16(nil, h))
		return
	}
	if f32 := float32(f); float64(f32) == f {
		e.buf.WriteByte(0xfa)
		e.buf.Write(binary.BigEndian.AppendUint32(nil, math.Float32bits(f32)))
		return
	}
	e.buf.WriteByte(0xfb)
	e.buf.Write(binary.BigEndian.AppendUint64(nil, math.Float64bits(f)))
}

// float64ToHalf returns the binary16 encoding of f if it is exact.
func float64ToHalf(f float64) (uint16, bool) {
	var sign uint16
	if math.Signbit(f) {
		sign = 0x8000
	}
	a := math.Abs(f)
	switch {
	case a == 0:
		return sign, true
	case math.IsInf(a, 0):
		return sign | 0x7c00, true
	}
	frac, exp := math.Frexp(a) // a = frac * 2^exp, frac in [0.5, 1)
	// Normal half range: 2^-14 <= a < 65520, 11 significant bits.
	if exp >= -13 && exp <= 16 {
		m := frac * 2048 // 11-bit significand including the implicit bit
		if m != math.Trunc(m) {
			return 0, false
		}
		e := uint16(exp + 14) // biased exponent: a = 1.x * 2^(exp-1), bias 15
		return sign | e<<10 | (uint16(m) & 0x3ff), true
	}
	// Subnormal half: a = m * 2^-24 with m < 1024.
	m := a * (1 << 24)
	if m == math.Trunc(m) && m < 1024 {
		return sign | uint16(m), true
	}
	return 0, false
}
