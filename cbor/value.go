// Package cbor implements the subset of RFC 8949 (Concise Binary Object
// Representation) that a WebAuthn relying party needs, plus enough of the
// rest of the format to pass the RFC's Appendix A examples.
//
// Decoding produces a tree of Value items. A decoded Value keeps a reference
// to the exact encoded bytes it came from (see Value.Raw), which WebAuthn
// needs because signatures and hashes are computed over the original bytes,
// never over a re-encoding.
//
// The decoder is defensive by construction: nesting depth and total item
// count are bounded, declared lengths are checked against the remaining input
// before anything is allocated, text strings must be valid UTF-8, and
// duplicate map keys are rejected by default.
package cbor

import (
	"bytes"
	"math"
)

// Kind identifies the type of a CBOR data item.
type Kind uint8

// Data item kinds. The first six correspond to CBOR major types 0-5, KindTag
// to major type 6, and KindSimple/KindFloat split major type 7.
const (
	KindInvalid Kind = iota
	KindUint
	KindNegInt
	KindBytes
	KindText
	KindArray
	KindMap
	KindTag
	KindSimple
	KindFloat
)

var kindNames = [...]string{"invalid", "uint", "negint", "bytes", "text", "array", "map", "tag", "simple", "float"}

// String returns a lowercase name for the kind.
func (k Kind) String() string {
	if int(k) < len(kindNames) {
		return kindNames[k]
	}
	return "unknown"
}

// Well-known simple values (RFC 8949 section 3.3).
const (
	SimpleFalse     = 20
	SimpleTrue      = 21
	SimpleNull      = 22
	SimpleUndefined = 23
)

// Value is one decoded (or to-be-encoded) CBOR data item. The zero Value is
// invalid. Values are immutable once constructed; slices returned by the
// accessors alias the Value's storage and must not be modified.
type Value struct {
	kind Kind
	// arg holds the integer argument: the unsigned value (KindUint), n for the
	// negative integer -1-n (KindNegInt), the tag number (KindTag) or the
	// simple value (KindSimple).
	arg   uint64
	f     float64
	data  []byte  // KindBytes / KindText payload
	items []Value // KindArray elements, or the single tagged item for KindTag
	pairs []Pair  // KindMap entries in encoded order
	// indefinite records that the item was encoded with an indefinite length.
	indefinite bool
	// raw is the exact encoded form of a decoded item (nil for constructed values).
	raw []byte
}

// Pair is one key/value entry of a CBOR map.
type Pair struct {
	Key   Value
	Value Value
}

// NewUint returns an unsigned integer item.
func NewUint(u uint64) Value { return Value{kind: KindUint, arg: u} }

// NewInt returns an integer item, choosing major type 0 or 1 by sign.
func NewInt(i int64) Value {
	if i >= 0 {
		return Value{kind: KindUint, arg: uint64(i)}
	}
	// -1-n = i  =>  n = -1-i, computed without overflow for math.MinInt64.
	return Value{kind: KindNegInt, arg: uint64(-(i + 1))} //nolint:gosec // i < 0, so -(i+1) is in [0, MaxInt64]
}

// NewNegInt returns the negative integer -1-n. It can represent values below
// math.MinInt64 that NewInt cannot.
func NewNegInt(n uint64) Value { return Value{kind: KindNegInt, arg: n} }

// NewBytes returns a byte string item. The slice is not copied.
func NewBytes(b []byte) Value {
	if b == nil {
		b = []byte{}
	}
	return Value{kind: KindBytes, data: b}
}

// NewText returns a text string item. s must be valid UTF-8 for the
// encoding to be well-formed.
func NewText(s string) Value { return Value{kind: KindText, data: []byte(s)} }

// NewArray returns an array item.
func NewArray(items ...Value) Value {
	if items == nil {
		items = []Value{}
	}
	return Value{kind: KindArray, items: items}
}

// NewMap returns a map item. Entries are encoded in the given order by
// Encode and in canonical order by EncodeCanonical.
func NewMap(pairs ...Pair) Value {
	if pairs == nil {
		pairs = []Pair{}
	}
	return Value{kind: KindMap, pairs: pairs}
}

// NewTag returns a tagged item.
func NewTag(number uint64, content Value) Value {
	return Value{kind: KindTag, arg: number, items: []Value{content}}
}

// NewBool returns true or false.
func NewBool(b bool) Value {
	if b {
		return Value{kind: KindSimple, arg: SimpleTrue}
	}
	return Value{kind: KindSimple, arg: SimpleFalse}
}

// Null returns the null item.
func Null() Value { return Value{kind: KindSimple, arg: SimpleNull} }

// Undefined returns the undefined item.
func Undefined() Value { return Value{kind: KindSimple, arg: SimpleUndefined} }

// NewSimple returns a simple value. Values 24..31 cannot be encoded in a
// well-formed way; Encode reports them via a panic-free fallback (see Encode).
func NewSimple(n uint8) Value { return Value{kind: KindSimple, arg: uint64(n)} }

// NewFloat returns a floating-point item. Encode uses the shortest IEEE 754
// width that represents f exactly.
func NewFloat(f float64) Value { return Value{kind: KindFloat, f: f} }

// Kind reports the item's kind.
func (v Value) Kind() Kind { return v.kind }

// Raw returns the exact encoded bytes of a decoded item, or nil for a
// constructed one.
func (v Value) Raw() []byte { return v.raw }

// Indefinite reports whether a decoded string, array or map used an
// indefinite-length encoding.
func (v Value) Indefinite() bool { return v.indefinite }

// Uint returns the value of an unsigned integer item.
func (v Value) Uint() (uint64, bool) { return v.arg, v.kind == KindUint }

// Int returns the value of an integer item that fits in an int64.
func (v Value) Int() (int64, bool) {
	switch v.kind {
	case KindUint:
		if v.arg > math.MaxInt64 {
			return 0, false
		}
		return int64(v.arg), true
	case KindNegInt:
		if v.arg > math.MaxInt64 {
			return 0, false
		}
		return -1 - int64(v.arg), true
	default:
		return 0, false
	}
}

// NegIntArg returns n for a negative integer item representing -1-n.
func (v Value) NegIntArg() (uint64, bool) { return v.arg, v.kind == KindNegInt }

// Bytes returns the payload of a byte string item.
func (v Value) Bytes() ([]byte, bool) {
	if v.kind != KindBytes {
		return nil, false
	}
	return v.data, true
}

// Text returns the payload of a text string item.
func (v Value) Text() (string, bool) {
	if v.kind != KindText {
		return "", false
	}
	return string(v.data), true
}

// Array returns the elements of an array item.
func (v Value) Array() ([]Value, bool) {
	if v.kind != KindArray {
		return nil, false
	}
	return v.items, true
}

// Map returns the entries of a map item in encoded order.
func (v Value) Map() ([]Pair, bool) {
	if v.kind != KindMap {
		return nil, false
	}
	return v.pairs, true
}

// Tag returns the tag number and content of a tagged item.
func (v Value) Tag() (uint64, Value, bool) {
	if v.kind != KindTag || len(v.items) != 1 {
		return 0, Value{}, false
	}
	return v.arg, v.items[0], true
}

// Simple returns the simple value number (including 20-23 for
// false/true/null/undefined).
func (v Value) Simple() (uint8, bool) {
	if v.kind != KindSimple || v.arg > math.MaxUint8 {
		return 0, false
	}
	return uint8(v.arg), true
}

// Bool returns the value of a true/false item.
func (v Value) Bool() (bool, bool) {
	if v.kind != KindSimple || (v.arg != SimpleFalse && v.arg != SimpleTrue) {
		return false, false
	}
	return v.arg == SimpleTrue, true
}

// IsNull reports whether the item is null.
func (v Value) IsNull() bool { return v.kind == KindSimple && v.arg == SimpleNull }

// Float returns the value of a floating-point item.
func (v Value) Float() (float64, bool) { return v.f, v.kind == KindFloat }

// Len returns the number of elements of an array, entries of a map, or
// bytes of a string; zero otherwise.
func (v Value) Len() int {
	switch v.kind {
	case KindArray:
		return len(v.items)
	case KindMap:
		return len(v.pairs)
	case KindBytes, KindText:
		return len(v.data)
	default:
		return 0
	}
}

// Lookup returns the value stored under key in a map item. Keys are compared
// by kind and content, so the integer 1 and the text "1" are distinct.
func (v Value) Lookup(key Value) (Value, bool) {
	if v.kind != KindMap {
		return Value{}, false
	}
	for _, p := range v.pairs {
		if Equal(p.Key, key) {
			return p.Value, true
		}
	}
	return Value{}, false
}

// LookupText is Lookup with a text-string key.
func (v Value) LookupText(key string) (Value, bool) { return v.Lookup(NewText(key)) }

// LookupInt is Lookup with an integer key.
func (v Value) LookupInt(key int64) (Value, bool) { return v.Lookup(NewInt(key)) }

// Equal reports whether two items are semantically identical: same kind,
// same content, same map entries in the same order. Encoding details such as
// indefinite lengths are ignored. NaN floats are equal to each other.
func Equal(a, b Value) bool {
	if a.kind != b.kind {
		return false
	}
	switch a.kind {
	case KindUint, KindNegInt, KindSimple:
		return a.arg == b.arg
	case KindFloat:
		if math.IsNaN(a.f) && math.IsNaN(b.f) {
			return true
		}
		return math.Float64bits(a.f) == math.Float64bits(b.f)
	case KindBytes, KindText:
		return bytes.Equal(a.data, b.data)
	case KindArray:
		if len(a.items) != len(b.items) {
			return false
		}
		for i := range a.items {
			if !Equal(a.items[i], b.items[i]) {
				return false
			}
		}
		return true
	case KindMap:
		if len(a.pairs) != len(b.pairs) {
			return false
		}
		for i := range a.pairs {
			if !Equal(a.pairs[i].Key, b.pairs[i].Key) || !Equal(a.pairs[i].Value, b.pairs[i].Value) {
				return false
			}
		}
		return true
	case KindTag:
		return a.arg == b.arg && len(a.items) == 1 && len(b.items) == 1 && Equal(a.items[0], b.items[0])
	default:
		return true
	}
}
