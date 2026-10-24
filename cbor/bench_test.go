package cbor

import (
	"encoding/hex"
	"testing"
)

// The "none" ES256 attestation object from the WebAuthn L3 test vectors
// (section 16.2), 194 bytes.
func benchInput(b *testing.B) []byte {
	b.Helper()
	in, err := hex.DecodeString("a363666d74646e6f6e656761747453746d74a068617574684461746158a4bfabc37432958b063360d3ad6461c9c4735ae7f8edd46592a5e0f01452b2e4b559000000008446ccb9ab1db374750b2367ff6f3a1f0020f91f391db4c9b2fde0ea70189cba3fb63f579ba6122b33ad94ff3ec330084be4a5010203262001215820afefa16f97ca9b2d23eb86ccb64098d20db90856062eb249c33a9b672f26df61225820930a56b87a2fca66334b03458abf879717c12cc68ed73290af2e2664796b9220")
	if err != nil {
		b.Fatal(err)
	}
	return in
}

func BenchmarkDecodeAttestationObject(b *testing.B) {
	in := benchInput(b)
	b.SetBytes(int64(len(in)))
	for b.Loop() {
		if _, err := Decode(in); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkEncodeCanonical(b *testing.B) {
	v, err := Decode(benchInput(b))
	if err != nil {
		b.Fatal(err)
	}
	for b.Loop() {
		_ = EncodeCanonical(v)
	}
}
