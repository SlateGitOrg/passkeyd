package cbor

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"unicode/utf8"
)

// Sentinel errors returned (wrapped in *DecodeError) by the decoder.
var (
	ErrUnexpectedEOF     = errors.New("cbor: unexpected end of input")
	ErrTrailingData      = errors.New("cbor: trailing data after item")
	ErrMalformed         = errors.New("cbor: malformed item")
	ErrDepthExceeded     = errors.New("cbor: nesting depth limit exceeded")
	ErrTooManyItems      = errors.New("cbor: item count limit exceeded")
	ErrDuplicateKey      = errors.New("cbor: duplicate map key")
	ErrIndefiniteLength  = errors.New("cbor: indefinite-length item not allowed")
	ErrNonCanonical      = errors.New("cbor: non-canonical encoding")
	ErrInvalidUTF8       = errors.New("cbor: text string is not valid UTF-8")
	ErrUnsupportedSimple = errors.New("cbor: reserved or ill-formed simple value")
)

// DecodeError reports where in the input decoding failed.
type DecodeError struct {
	Offset int   // byte offset of the item that failed
	Err    error // one of the sentinel errors above
	Detail string
}

func (e *DecodeError) Error() string {
	if e.Detail != "" {
		return fmt.Sprintf("%v at offset %d: %s", e.Err, e.Offset, e.Detail)
	}
	return fmt.Sprintf("%v at offset %d", e.Err, e.Offset)
}

// Unwrap returns the sentinel error.
func (e *DecodeError) Unwrap() error { return e.Err }

// Options controls decoder strictness and resource limits.
type Options struct {
	// MaxDepth bounds the nesting of arrays, maps and tags. Zero means 16.
	MaxDepth int
	// MaxItems bounds the total number of data items decoded. Zero means 1<<16.
	MaxItems int
	// AllowIndefinite permits indefinite-length strings, arrays and maps.
	AllowIndefinite bool
	// AllowDuplicateKeys disables the duplicate map key check.
	AllowDuplicateKeys bool
	// Canonical requires the CTAP2 canonical form: shortest-form arguments,
	// definite lengths, and map keys sorted length-first then bytewise.
	Canonical bool
}

// GenericOptions decodes any well-formed CBOR that RFC 8949 Appendix A
// exercises, while keeping the resource limits and duplicate-key check.
var GenericOptions = Options{AllowIndefinite: true}

// StrictOptions is the profile used for WebAuthn structures: definite
// lengths only and no duplicate keys. Key order and shortest-form arguments
// are not enforced because conforming clients are not required to
// re-canonicalize authenticator output.
var StrictOptions = Options{}

const (
	defaultMaxDepth = 16
	defaultMaxItems = 1 << 16
)

// Decode decodes exactly one data item from data using StrictOptions. Any
// bytes after the item produce ErrTrailingData. The returned Value aliases
// data.
func Decode(data []byte) (Value, error) { return DecodeWith(data, StrictOptions) }

// DecodeWith is Decode with explicit options.
func DecodeWith(data []byte, opts Options) (Value, error) {
	v, rest, err := DecodeFirstWith(data, opts)
	if err != nil {
		return Value{}, err
	}
	if len(rest) != 0 {
		return Value{}, &DecodeError{Offset: len(data) - len(rest), Err: ErrTrailingData}
	}
	return v, nil
}

// DecodeFirst decodes one data item from the front of data with
// StrictOptions and returns the remaining bytes. WebAuthn uses it to find
// where the COSE public key ends inside authenticator data.
func DecodeFirst(data []byte) (Value, []byte, error) { return DecodeFirstWith(data, StrictOptions) }

// DecodeFirstWith is DecodeFirst with explicit options.
func DecodeFirstWith(data []byte, opts Options) (Value, []byte, error) {
	if opts.MaxDepth <= 0 {
		opts.MaxDepth = defaultMaxDepth
	}
	if opts.MaxItems <= 0 {
		opts.MaxItems = defaultMaxItems
	}
	if opts.Canonical {
		opts.AllowIndefinite = false
	}
	d := decoder{data: data, opts: opts}
	v, err := d.item(0)
	if err != nil {
		return Value{}, nil, err
	}
	return v, data[d.off:], nil
}

type decoder struct {
	data  []byte
	off   int
	items int
	opts  Options
}

func (d *decoder) fail(at int, err error, detail string) error {
	return &DecodeError{Offset: at, Err: err, Detail: detail}
}

// header reads an initial byte and its argument. For ai==31 it returns
// indefinite=true and arg 0.
func (d *decoder) header() (major byte, ai byte, arg uint64, indefinite bool, err error) {
	start := d.off
	if d.off >= len(d.data) {
		return 0, 0, 0, false, d.fail(start, ErrUnexpectedEOF, "")
	}
	ib := d.data[d.off]
	d.off++
	major, ai = ib>>5, ib&0x1f
	switch {
	case ai < 24:
		return major, ai, uint64(ai), false, nil
	case ai <= 27:
		n := 1 << (ai - 24)
		if len(d.data)-d.off < n {
			return 0, 0, 0, false, d.fail(start, ErrUnexpectedEOF, "truncated argument")
		}
		b := d.data[d.off : d.off+n]
		d.off += n
		switch n {
		case 1:
			arg = uint64(b[0])
		case 2:
			arg = uint64(binary.BigEndian.Uint16(b))
		case 4:
			arg = uint64(binary.BigEndian.Uint32(b))
		default:
			arg = binary.BigEndian.Uint64(b)
		}
		if d.opts.Canonical && major != 7 && !shortest(ai, arg) {
			return 0, 0, 0, false, d.fail(start, ErrNonCanonical, "argument not in shortest form")
		}
		return major, ai, arg, false, nil
	case ai == 31:
		return major, ai, 0, true, nil
	default:
		return 0, 0, 0, false, d.fail(start, ErrMalformed, fmt.Sprintf("reserved additional information %d", ai))
	}
}

func shortest(ai byte, arg uint64) bool {
	switch ai {
	case 24:
		return arg >= 24
	case 25:
		return arg > math.MaxUint8
	case 26:
		return arg > math.MaxUint16
	case 27:
		return arg > math.MaxUint32
	}
	return true
}

func (d *decoder) item(depth int) (Value, error) {
	start := d.off
	d.items++
	if d.items > d.opts.MaxItems {
		return Value{}, d.fail(start, ErrTooManyItems, "")
	}
	major, ai, arg, indef, err := d.header()
	if err != nil {
		return Value{}, err
	}
	var v Value
	switch major {
	case 0:
		if indef {
			return Value{}, d.fail(start, ErrMalformed, "indefinite length on integer")
		}
		v = Value{kind: KindUint, arg: arg}
	case 1:
		if indef {
			return Value{}, d.fail(start, ErrMalformed, "indefinite length on integer")
		}
		v = Value{kind: KindNegInt, arg: arg}
	case 2, 3:
		v, err = d.str(start, major, arg, indef)
	case 4:
		v, err = d.array(start, depth, arg, indef)
	case 5:
		v, err = d.mapItem(start, depth, arg, indef)
	case 6:
		if indef {
			return Value{}, d.fail(start, ErrMalformed, "indefinite length on tag")
		}
		if depth+1 > d.opts.MaxDepth {
			return Value{}, d.fail(start, ErrDepthExceeded, "")
		}
		var content Value
		content, err = d.item(depth + 1)
		v = Value{kind: KindTag, arg: arg, items: []Value{content}}
	default: // 7
		v, err = d.simpleOrFloat(start, ai, arg, indef)
	}
	if err != nil {
		return Value{}, err
	}
	v.raw = d.data[start:d.off]
	return v, nil
}

func (d *decoder) str(start int, major byte, n uint64, indef bool) (Value, error) {
	kind := KindBytes
	if major == 3 {
		kind = KindText
	}
	var payload []byte
	if indef {
		if !d.opts.AllowIndefinite {
			return Value{}, d.fail(start, ErrIndefiniteLength, "")
		}
		payload = []byte{}
		for {
			if d.off >= len(d.data) {
				return Value{}, d.fail(start, ErrUnexpectedEOF, "unterminated indefinite string")
			}
			if d.data[d.off] == 0xff {
				d.off++
				break
			}
			chunkStart := d.off
			cm, _, cn, cindef, err := d.header()
			if err != nil {
				return Value{}, err
			}
			if cm != major || cindef {
				return Value{}, d.fail(chunkStart, ErrMalformed, "indefinite string chunk of wrong type")
			}
			chunk, err := d.take(chunkStart, cn)
			if err != nil {
				return Value{}, err
			}
			if kind == KindText && !utf8.Valid(chunk) {
				return Value{}, d.fail(chunkStart, ErrInvalidUTF8, "")
			}
			payload = append(payload, chunk...)
		}
	} else {
		var err error
		if payload, err = d.take(start, n); err != nil {
			return Value{}, err
		}
	}
	if kind == KindText && !utf8.Valid(payload) {
		return Value{}, d.fail(start, ErrInvalidUTF8, "")
	}
	return Value{kind: kind, data: payload, indefinite: indef}, nil
}

func (d *decoder) take(start int, n uint64) ([]byte, error) {
	rem := len(d.data) - d.off // never negative: off only advances within data
	if n > uint64(rem) {       //nolint:gosec // rem >= 0
		return nil, d.fail(start, ErrUnexpectedEOF, fmt.Sprintf("string of length %d exceeds remaining input", n))
	}
	size := int(n) //nolint:gosec // n <= rem, which is an int
	b := d.data[d.off : d.off+size]
	d.off += size
	return b, nil
}

// atBreak consumes a break byte if one is next.
func (d *decoder) atBreak(start int) (bool, error) {
	if d.off >= len(d.data) {
		return false, d.fail(start, ErrUnexpectedEOF, "unterminated indefinite container")
	}
	if d.data[d.off] == 0xff {
		d.off++
		return true, nil
	}
	return false, nil
}

func (d *decoder) array(start, depth int, n uint64, indef bool) (Value, error) {
	if depth+1 > d.opts.MaxDepth {
		return Value{}, d.fail(start, ErrDepthExceeded, "")
	}
	if indef && !d.opts.AllowIndefinite {
		return Value{}, d.fail(start, ErrIndefiniteLength, "")
	}
	// Every element needs at least one byte, so a declared count larger than
	// the remaining input is malformed; checking first avoids a huge allocation.
	if !indef && n > uint64(len(d.data)-d.off) { //nolint:gosec // remaining input length is >= 0
		return Value{}, d.fail(start, ErrUnexpectedEOF, fmt.Sprintf("array of %d items exceeds remaining input", n))
	}
	items := make([]Value, 0, int(n)) //nolint:gosec // n is bounded by the input length above
	for i := uint64(0); indef || i < n; i++ {
		if indef {
			done, err := d.atBreak(start)
			if err != nil {
				return Value{}, err
			}
			if done {
				break
			}
		}
		it, err := d.item(depth + 1)
		if err != nil {
			return Value{}, err
		}
		items = append(items, it)
	}
	return Value{kind: KindArray, items: items, indefinite: indef}, nil
}

func (d *decoder) mapItem(start, depth int, n uint64, indef bool) (Value, error) {
	if depth+1 > d.opts.MaxDepth {
		return Value{}, d.fail(start, ErrDepthExceeded, "")
	}
	if indef && !d.opts.AllowIndefinite {
		return Value{}, d.fail(start, ErrIndefiniteLength, "")
	}
	if !indef && n > uint64(len(d.data)-d.off)/2 { //nolint:gosec // remaining input length is >= 0
		return Value{}, d.fail(start, ErrUnexpectedEOF, fmt.Sprintf("map of %d entries exceeds remaining input", n))
	}
	pairs := make([]Pair, 0, int(n)) //nolint:gosec // n is bounded by the input length above
	var seen keySet
	for i := uint64(0); indef || i < n; i++ {
		if indef {
			done, err := d.atBreak(start)
			if err != nil {
				return Value{}, err
			}
			if done {
				break
			}
		}
		keyStart := d.off
		k, err := d.item(depth + 1)
		if err != nil {
			return Value{}, err
		}
		val, err := d.item(depth + 1)
		if err != nil {
			return Value{}, err
		}
		if d.opts.Canonical && len(pairs) > 0 && canonicalCompare(k.raw, pairs[len(pairs)-1].Key.raw) <= 0 {
			return Value{}, d.fail(keyStart, ErrNonCanonical, "map keys not in canonical order")
		}
		if !d.opts.AllowDuplicateKeys && seen.add(pairs, k) {
			return Value{}, d.fail(keyStart, ErrDuplicateKey, "")
		}
		pairs = append(pairs, Pair{Key: k, Value: val})
	}
	return Value{kind: KindMap, pairs: pairs, indefinite: indef}, nil
}

func (d *decoder) simpleOrFloat(start int, ai byte, arg uint64, indef bool) (Value, error) {
	switch {
	case indef:
		// A break byte outside an indefinite container.
		return Value{}, d.fail(start, ErrMalformed, "unexpected break")
	case ai < 24:
		return Value{kind: KindSimple, arg: arg}, nil
	case ai == 24:
		if arg < 32 {
			return Value{}, d.fail(start, ErrUnsupportedSimple, fmt.Sprintf("simple(%d) in two-byte form", arg))
		}
		return Value{kind: KindSimple, arg: arg}, nil
	case ai == 25:
		return Value{kind: KindFloat, f: halfToFloat64(uint16(arg))}, nil //nolint:gosec // ai 25 carries a 2-byte argument
	case ai == 26:
		return Value{kind: KindFloat, f: float64(math.Float32frombits(uint32(arg)))}, nil //nolint:gosec // ai 26 carries a 4-byte argument
	default: // 27
		return Value{kind: KindFloat, f: math.Float64frombits(arg)}, nil
	}
}

// halfToFloat64 converts an IEEE 754 binary16 value (RFC 8949 Appendix D).
func halfToFloat64(h uint16) float64 {
	exp := int(h>>10) & 0x1f
	mant := float64(h & 0x3ff)
	var val float64
	switch exp {
	case 0:
		val = math.Ldexp(mant, -24)
	case 31:
		if mant == 0 {
			val = math.Inf(1)
		} else {
			val = math.NaN()
		}
	default:
		val = math.Ldexp(mant+1024, exp-25)
	}
	if h&0x8000 != 0 {
		return -val
	}
	return val
}

// smallMapScan is the map size up to which duplicate detection scans
// linearly; larger maps switch to a hash set so a hostile map of many
// distinct keys costs O(k) rather than O(k^2).
const smallMapScan = 16

// keySet detects duplicate map keys. Keys are compared by their preferred
// serialization, which is equal exactly when Equal reports equality (it
// normalizes argument widths and indefinite lengths).
type keySet struct{ set map[string]struct{} }

// add reports whether k duplicates a key already in pairs, recording it.
func (s *keySet) add(pairs []Pair, k Value) bool {
	if s.set == nil {
		if len(pairs) < smallMapScan {
			for _, p := range pairs {
				if Equal(p.Key, k) {
					return true
				}
			}
			return false
		}
		s.set = make(map[string]struct{}, 2*len(pairs))
		for _, p := range pairs {
			s.set[string(Encode(p.Key))] = struct{}{}
		}
	}
	enc := string(Encode(k))
	if _, dup := s.set[enc]; dup {
		return true
	}
	s.set[enc] = struct{}{}
	return false
}
