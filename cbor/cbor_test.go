package cbor

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math"
	"math/big"
	"math/rand/v2"
	"os"
	"strings"
	"testing"
	"time"
)

type appendixVector struct {
	Hex        string          `json:"hex"`
	Roundtrip  bool            `json:"roundtrip"`
	Decoded    json.RawMessage `json:"decoded"`
	Diagnostic string          `json:"diagnostic"`
}

func loadAppendixA(t *testing.T) []appendixVector {
	t.Helper()
	raw, err := os.ReadFile("../testdata/cbor-appendix-a.json")
	if err != nil {
		t.Fatal(err)
	}
	var vs []appendixVector
	if err := json.Unmarshal(raw, &vs); err != nil {
		t.Fatal(err)
	}
	return vs
}

// TestAppendixA runs every example from the RFC 7049 / RFC 8949 Appendix A
// list: decode, compare with the JSON or diagnostic expectation, and
// re-encode where a generic encoder is expected to round-trip.
//
// One example, f818 = simple(24), was valid under RFC 7049 but is not
// well-formed under RFC 8949 section 3.3 (simple values below 32 must use the
// one-byte form), so this decoder rejects it.
func TestAppendixA(t *testing.T) {
	vs := loadAppendixA(t)
	if len(vs) != 82 {
		t.Fatalf("expected 82 vectors, got %d", len(vs))
	}
	for _, tv := range vs {
		t.Run(tv.Hex, func(t *testing.T) {
			in, err := hex.DecodeString(tv.Hex)
			if err != nil {
				t.Fatal(err)
			}
			v, err := DecodeWith(in, GenericOptions)
			if tv.Hex == "f818" {
				if !errors.Is(err, ErrUnsupportedSimple) {
					t.Fatalf("simple(24) must be rejected per RFC 8949, got %v", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("decode: %v", err)
			}
			if !bytes.Equal(v.Raw(), in) {
				t.Errorf("Raw() does not cover the input")
			}
			if tv.Decoded != nil {
				dec := json.NewDecoder(bytes.NewReader(tv.Decoded))
				dec.UseNumber()
				var want any
				if err := dec.Decode(&want); err != nil {
					t.Fatal(err)
				}
				if !jsonEqual(t, v, want) {
					t.Errorf("decoded %s, want %s", Diagnostic(v), tv.Decoded)
				}
			} else {
				want := tv.Diagnostic
				if want == "(_ h'0102', h'030405')" {
					want = "h'0102030405'" // chunks are concatenated by design
				}
				if got := Diagnostic(v); got != want {
					t.Errorf("diagnostic %q, want %q", got, want)
				}
			}
			if tv.Roundtrip {
				if got := Encode(v); !bytes.Equal(got, in) {
					t.Errorf("re-encode %x, want %x", got, in)
				}
			}
		})
	}
}

func bigOf(v Value) (*big.Int, bool) {
	switch v.Kind() {
	case KindUint:
		return new(big.Int).SetUint64(v.arg), true
	case KindNegInt:
		n := new(big.Int).SetUint64(v.arg)
		return n.Neg(n).Sub(n, big.NewInt(1)), true
	case KindTag:
		num, c, _ := v.Tag()
		b, ok := c.Bytes()
		if !ok || (num != 2 && num != 3) {
			return nil, false
		}
		n := new(big.Int).SetBytes(b)
		if num == 3 {
			n.Neg(n).Sub(n, big.NewInt(1))
		}
		return n, true
	}
	return nil, false
}

func jsonEqual(t *testing.T, v Value, want any) bool {
	t.Helper()
	switch w := want.(type) {
	case json.Number:
		s := w.String()
		if f, ok := v.Float(); ok {
			wf, err := w.Float64()
			return err == nil && (f == wf) && math.Signbit(f) == strings.HasPrefix(s, "-")
		}
		n, ok := bigOf(v)
		if !ok {
			return false
		}
		wn, ok := new(big.Int).SetString(s, 10)
		return ok && n.Cmp(wn) == 0
	case bool:
		b, ok := v.Bool()
		return ok && b == w
	case nil:
		return v.IsNull()
	case string:
		s, ok := v.Text()
		return ok && s == w
	case []any:
		items, ok := v.Array()
		if !ok || len(items) != len(w) {
			return false
		}
		for i := range items {
			if !jsonEqual(t, items[i], w[i]) {
				return false
			}
		}
		return true
	case map[string]any:
		pairs, ok := v.Map()
		if !ok || len(pairs) != len(w) {
			return false
		}
		for _, p := range pairs {
			k, ok := p.Key.Text()
			if !ok || !jsonEqual(t, p.Value, w[k]) {
				return false
			}
		}
		return true
	}
	return false
}

func mustHex(t testing.TB, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(strings.ReplaceAll(s, " ", ""))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// TestDecodeErrors is the negative table: every sentinel error has at least
// one input that triggers it.
func TestDecodeErrors(t *testing.T) {
	deep := bytes.Repeat([]byte{0x81}, 20)
	deep = append(deep, 0x00)
	cases := []struct {
		name string
		in   string
		opts Options
		want error
	}{
		{"empty", "", StrictOptions, ErrUnexpectedEOF},
		{"truncated uint16", "19 01", StrictOptions, ErrUnexpectedEOF},
		{"truncated bytes", "44 0102", StrictOptions, ErrUnexpectedEOF},
		{"huge array count", "9b 7fffffffffffffff", StrictOptions, ErrUnexpectedEOF},
		{"huge map count", "bb 7fffffffffffffff", StrictOptions, ErrUnexpectedEOF},
		{"huge byte length", "5b 7fffffffffffffff 00", StrictOptions, ErrUnexpectedEOF},
		{"unterminated indefinite array", "9f 01", GenericOptions, ErrUnexpectedEOF},
		{"unterminated indefinite string", "5f 41 00", GenericOptions, ErrUnexpectedEOF},
		{"trailing", "00 00", StrictOptions, ErrTrailingData},
		{"reserved ai 28", "1c", StrictOptions, ErrMalformed},
		{"reserved ai 30 on bytes", "5e", StrictOptions, ErrMalformed},
		{"indefinite uint", "1f", StrictOptions, ErrMalformed},
		{"indefinite negint", "3f", StrictOptions, ErrMalformed},
		{"indefinite tag", "df", StrictOptions, ErrMalformed},
		{"lone break", "ff", StrictOptions, ErrMalformed},
		{"text chunk in byte string", "5f 61 61 ff", GenericOptions, ErrMalformed},
		{"nested indefinite chunk", "5f 5f ff ff", GenericOptions, ErrMalformed},
		{"indefinite in strict", "9f ff", StrictOptions, ErrIndefiniteLength},
		{"indefinite map in strict", "bf ff", StrictOptions, ErrIndefiniteLength},
		{"indefinite bytes in strict", "5f ff", StrictOptions, ErrIndefiniteLength},
		{"duplicate int key", "a2 01 00 01 00", StrictOptions, ErrDuplicateKey},
		{"duplicate text key", "a2 6161 00 6161 01", StrictOptions, ErrDuplicateKey},
		{"invalid utf8", "62 c328", StrictOptions, ErrInvalidUTF8},
		{"invalid utf8 chunk", "7f 61 ff ff", GenericOptions, ErrInvalidUTF8},
		{"simple 24 in two bytes", "f8 18", StrictOptions, ErrUnsupportedSimple},
		{"non-shortest uint", "18 17", Options{Canonical: true}, ErrNonCanonical},
		{"non-shortest length", "59 0001 00", Options{Canonical: true}, ErrNonCanonical},
		{"unsorted keys", "a2 02 00 01 00", Options{Canonical: true}, ErrNonCanonical},
		{"longer key first", "a2 1818 00 01 00", Options{Canonical: true}, ErrNonCanonical},
		{"depth", hex.EncodeToString(deep), StrictOptions, ErrDepthExceeded},
		{"tag depth", "c1 c1 c1 00", Options{MaxDepth: 2}, ErrDepthExceeded},
		{"map depth", "a1 00 a1 00 00", Options{MaxDepth: 1}, ErrDepthExceeded},
		{"too many items", "83 01 02 03", Options{MaxItems: 3}, ErrTooManyItems},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := DecodeWith(mustHex(t, tc.in), tc.opts)
			if !errors.Is(err, tc.want) {
				t.Fatalf("got %v, want %v", err, tc.want)
			}
			var de *DecodeError
			if !errors.As(err, &de) || de.Error() == "" {
				t.Fatalf("error %T is not a *DecodeError", err)
			}
		})
	}
}

// TestLargeMapDuplicateDetection covers the hash-set path: a map with many
// distinct keys decodes in linear time, and a duplicate far into the map —
// including one written in a non-shortest form — is still caught.
func TestLargeMapDuplicateDetection(t *testing.T) {
	const n = 20000
	build := func(extra []byte) []byte {
		buf := []byte{0xb9, byte((n + len(extra)/3) >> 8), byte(n + len(extra)/3)}
		for i := range n {
			buf = append(buf, 0x19, byte(i>>8), byte(i), 0x00)
		}
		return append(buf, extra...)
	}
	start := time.Now()
	v, err := Decode(build(nil))
	if err != nil || v.Len() != n {
		t.Fatalf("len %d err %v", v.Len(), err)
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Fatalf("decoding %d distinct keys took %v", n, d)
	}
	// Key 5 again, encoded as a 1-byte argument (18 05) instead of 05.
	if _, err := Decode(build([]byte{0x18, 0x05, 0x00})); !errors.Is(err, ErrDuplicateKey) {
		t.Fatalf("got %v", err)
	}
}

func TestDuplicateKeysAllowedWhenRequested(t *testing.T) {
	v, err := DecodeWith(mustHex(t, "a2 01 00 01 01"), Options{AllowDuplicateKeys: true})
	if err != nil || v.Len() != 2 {
		t.Fatalf("got %v %v", v.Len(), err)
	}
}

func TestDecodeFirstReturnsRest(t *testing.T) {
	v, rest, err := DecodeFirst(mustHex(t, "a1 01 02 ff ee"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(rest, []byte{0xff, 0xee}) || !bytes.Equal(v.Raw(), mustHex(t, "a10102")) {
		t.Fatalf("rest=%x raw=%x", rest, v.Raw())
	}
	if _, _, err := DecodeFirst(nil); !errors.Is(err, ErrUnexpectedEOF) {
		t.Fatal(err)
	}
}

func TestCanonicalAcceptsCanonical(t *testing.T) {
	v := NewMap(
		Pair{NewText("bb"), NewUint(1)},
		Pair{NewInt(-1), NewUint(2)},
		Pair{NewUint(3), NewArray(NewUint(1000))},
		Pair{NewText("a"), NewTag(1, NewFloat(1.5))},
	)
	enc := EncodeCanonical(v)
	got, err := DecodeWith(enc, Options{Canonical: true})
	if err != nil {
		t.Fatalf("canonical decode of canonical output: %v (%x)", err, enc)
	}
	// Canonical order: 03, 20, 61 61, 62 62 62.
	keys := []string{}
	pairs, _ := got.Map()
	for _, p := range pairs {
		keys = append(keys, hex.EncodeToString(p.Key.Raw()))
	}
	if strings.Join(keys, ",") != "03,20,6161,626262" {
		t.Fatalf("key order %v", keys)
	}
}

func TestAccessors(t *testing.T) {
	m := NewMap(
		Pair{NewInt(1), NewInt(-7)},
		Pair{NewText("x"), NewBytes([]byte{1, 2})},
		Pair{NewInt(-2), NewBool(true)},
	)
	d, err := Decode(Encode(m))
	if err != nil {
		t.Fatal(err)
	}
	if v, ok := d.LookupInt(1); !ok {
		t.Fatal("missing key 1")
	} else if i, ok := v.Int(); !ok || i != -7 {
		t.Fatalf("got %v", i)
	}
	if v, ok := d.LookupText("x"); !ok || v.Len() != 2 {
		t.Fatal("missing x")
	}
	if _, ok := d.LookupText("1"); ok {
		t.Fatal("text key must not match int key")
	}
	if v, _ := d.LookupInt(-2); !mustBool(v) {
		t.Fatal("bool")
	}
	if _, ok := NewText("a").Lookup(NewInt(1)); ok {
		t.Fatal("lookup on non-map")
	}
	if _, ok := NewUint(math.MaxUint64).Int(); ok {
		t.Fatal("uint64 max must not fit int64")
	}
	if _, ok := NewNegInt(math.MaxUint64).Int(); ok {
		t.Fatal("-2^64 must not fit int64")
	}
	if i, ok := NewInt(math.MinInt64).Int(); !ok || i != math.MinInt64 {
		t.Fatal("MinInt64 round trip")
	}
	if n, ok := NewInt(-5).NegIntArg(); !ok || n != 4 {
		t.Fatal("NegIntArg")
	}
	if _, ok := NewInt(1).Bytes(); ok {
		t.Fatal("Bytes on int")
	}
	if _, ok := NewInt(1).Text(); ok {
		t.Fatal("Text on int")
	}
	if _, ok := NewInt(1).Array(); ok {
		t.Fatal("Array on int")
	}
	if _, ok := NewInt(1).Map(); ok {
		t.Fatal("Map on int")
	}
	if _, _, ok := NewInt(1).Tag(); ok {
		t.Fatal("Tag on int")
	}
	if _, ok := NewInt(1).Bool(); ok {
		t.Fatal("Bool on int")
	}
	if s, ok := NewSimple(16).Simple(); !ok || s != 16 {
		t.Fatal("Simple")
	}
	if _, ok := NewInt(1).Simple(); ok {
		t.Fatal("Simple on int")
	}
	if NewInt(1).Len() != 0 || NewArray(NewInt(1)).Len() != 1 {
		t.Fatal("Len")
	}
	if KindMap.String() != "map" || Kind(99).String() != "unknown" {
		t.Fatal("Kind.String")
	}
	if Diagnostic(Value{}) != "<invalid>" || Diagnostic(Undefined()) != "undefined" || Diagnostic(Null()) != "null" {
		t.Fatal("diag specials")
	}
	if NewBytes(nil).Len() != 0 || NewArray().Len() != 0 || NewMap().Len() != 0 {
		t.Fatal("empty constructors")
	}
}

func mustBool(v Value) bool { b, _ := v.Bool(); return b }

func TestEncodeEdgeCases(t *testing.T) {
	cases := []struct {
		v    Value
		want string
	}{
		{NewSimple(25), "f7"},    // ill-formed simple falls back to undefined
		{Value{}, "f7"},          // invalid value
		{NewSimple(200), "f8c8"}, // two-byte simple
		{NewFloat(math.NaN()), "f97e00"},
		{NewFloat(math.Inf(-1)), "f9fc00"},
		{NewFloat(math.Copysign(0, -1)), "f98000"},
		{NewFloat(65504), "f97bff"},
		{NewFloat(65505), "fa477fe100"},
		{NewFloat(1.0 / 3), "fb3fd5555555555555"},
		{NewFloat(math.Ldexp(1, -20)), "f90010"}, // half subnormal
		{NewInt(-1 << 40), "3b000000ffffffffff"},
		{NewUint(1 << 32), "1b0000000100000000"},
		{NewUint(65536), "1a00010000"},
	}
	for _, tc := range cases {
		if got := hex.EncodeToString(Encode(tc.v)); got != tc.want {
			t.Errorf("Encode(%s) = %s, want %s", Diagnostic(tc.v), got, tc.want)
		}
	}
	if got := Diagnostic(NewFloat(1e-7)); got != "1e-07" {
		t.Errorf("small float diag %q", got)
	}
	if got := Diagnostic(NewFloat(2)); got != "2.0" {
		t.Errorf("integral float diag %q", got)
	}
}

func TestEqual(t *testing.T) {
	a := NewMap(Pair{NewInt(1), NewArray(NewFloat(math.NaN()), NewTag(2, NewBytes([]byte{1})))})
	b := NewMap(Pair{NewInt(1), NewArray(NewFloat(math.NaN()), NewTag(2, NewBytes([]byte{1})))})
	if !Equal(a, b) {
		t.Fatal("expected equal")
	}
	c := NewMap(Pair{NewInt(1), NewArray(NewFloat(math.NaN()), NewTag(3, NewBytes([]byte{1})))})
	if Equal(a, c) || Equal(NewInt(1), NewText("1")) || Equal(NewArray(NewInt(1)), NewArray()) {
		t.Fatal("expected unequal")
	}
	if Equal(NewMap(Pair{NewInt(1), NewInt(1)}), NewMap(Pair{NewInt(1), NewInt(2)})) {
		t.Fatal("map values differ")
	}
	if Equal(NewMap(), NewMap(Pair{NewInt(1), NewInt(2)})) {
		t.Fatal("map sizes differ")
	}
}

// randomValue builds an arbitrary item for the round-trip property.
func randomValue(r *rand.Rand, depth int) Value {
	n := 9
	if depth > 3 {
		n = 6
	}
	switch r.IntN(n) {
	case 0:
		return NewUint(r.Uint64() >> r.UintN(64))
	case 1:
		return NewNegInt(r.Uint64() >> r.UintN(64))
	case 2:
		b := make([]byte, r.IntN(40))
		for i := range b {
			b[i] = byte(r.UintN(256))
		}
		return NewBytes(b)
	case 3:
		return NewText(strings.Repeat("é", r.IntN(5)) + "x")
	case 4:
		return []Value{NewBool(true), NewBool(false), Null(), Undefined(), NewSimple(uint8(32 + r.IntN(200)))}[r.IntN(5)]
	case 5:
		return NewFloat([]float64{0, 1.5, -2.25, r.NormFloat64(), math.Inf(1), float64(float32(r.Float64()))}[r.IntN(6)])
	case 6:
		items := make([]Value, r.IntN(5))
		for i := range items {
			items[i] = randomValue(r, depth+1)
		}
		return NewArray(items...)
	case 7:
		var pairs []Pair
		for i := range r.IntN(5) {
			pairs = append(pairs, Pair{NewUint(uint64(i)), randomValue(r, depth+1)})
		}
		return NewMap(pairs...)
	default:
		return NewTag(r.Uint64()>>r.UintN(64), randomValue(r, depth+1))
	}
}

// TestRoundTripProperty: for random items, decode(encode(v)) == v, the
// canonical encoding passes the canonical decoder, and encoding is stable.
func TestRoundTripProperty(t *testing.T) {
	r := rand.New(rand.NewPCG(1, 2))
	for i := range 3000 {
		v := randomValue(r, 0)
		enc := Encode(v)
		got, err := Decode(enc)
		if err != nil {
			t.Fatalf("iter %d: decode(%x): %v", i, enc, err)
		}
		if !Equal(got, v) {
			t.Fatalf("iter %d: %s != %s", i, Diagnostic(got), Diagnostic(v))
		}
		if !bytes.Equal(Encode(got), enc) {
			t.Fatalf("iter %d: encoding not stable", i)
		}
		if _, err := DecodeWith(EncodeCanonical(v), Options{Canonical: true}); err != nil {
			t.Fatalf("iter %d: canonical: %v", i, err)
		}
	}
}

func FuzzDecode(f *testing.F) {
	for _, s := range []string{"00", "a26161016162820203", "9f018202039f0405ffff", "c249010000000000000000",
		"a501020326200121582000000000000000000000000000000000000000000000000000000000000000002258200000000000000000000000000000000000000000000000000000000000000000",
		"f97e00", "5f42010243030405ff", "bf6346756ef563416d7421ff"} {
		b, _ := hex.DecodeString(s)
		f.Add(b)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		v, err := DecodeWith(data, GenericOptions)
		if err != nil {
			return
		}
		if !bytes.Equal(v.Raw(), data) {
			t.Fatalf("raw mismatch")
		}
		_ = Diagnostic(v)
		enc := Encode(v)
		again, err := DecodeWith(enc, GenericOptions)
		if err != nil {
			t.Fatalf("re-decode of %x failed: %v", enc, err)
		}
		if !Equal(v, again) {
			t.Fatalf("round trip changed value: %s vs %s", Diagnostic(v), Diagnostic(again))
		}
	})
}
