# Data

passkeyd commits two small public test-vector files. Nothing is downloaded at
test time, and no personal data is involved.

## testdata/webauthn-l3-vectors.json (41.6 KB)

- **Contents:** every credential example in the WebAuthn Level 3 test vectors
  section (§16: attestation root certificate; none ES256 plus its crossOrigin,
  topOrigin and 1023-byte credential-ID variants; packed self ES256; packed
  x5c ES256, ES384, ES512, RS256, EdDSA and Ed448), as hex strings for each
  ceremony.
- **Source:** W3C, *Web Authentication: An API for accessing Public Key
  Credentials, Level 3*, editor's draft, <https://w3c.github.io/webauthn/#sctn-test-vectors>,
  fetched 2026-10-24. The SHA-256 of the fetched HTML was
  `4db7b59b76c7d163c18c460d3f7d735a862a76ce7fa09ab51f006839e9a2c969`.
- **Extraction:** `python3 scripts/extract_vectors.py <spec.html> > testdata/webauthn-l3-vectors.json`
  (or `make vectors SPEC=<spec.html>`). The script uses only the standard
  library, strips HTML, and collects every `name = h'…'` assignment for each
  subsection and ceremony.
- **Committed file SHA-256:** `785aed0b97b3bf5814f6884ced731285cb062b55845bcfc4f8826ad01462968e`.
- **License:** W3C Software and Document License
  (<https://www.w3.org/copyright/software-license/>). This is a permissive
  license, and the vectors are reproduced with attribution.
- **Nature:** synthetic. The vectors are generated deterministically with
  HKDF-SHA-256 from the seed "WebAuthn test vectors", as the spec describes.

## testdata/cbor-appendix-a.json (10.3 KB)

- **Contents:** 82 examples from the CBOR specification's Appendix A, each
  with its hex encoding and either the decoded JSON value or the diagnostic
  notation.
- **Source:** <https://github.com/cbor/test-vectors> (`appendix_a.json`, last
  updated 2019-08-07). It reproduces RFC 7049 Appendix A. RFC 8949 obsoletes
  RFC 7049, and its §3.3 makes one of those examples (`f818`, `simple(24)`)
  ill-formed, so the test expects that example to be rejected.
- **Committed file SHA-256:** `80e78dc2f53cfdc9836094791d09e84c6818edf380f7cdd4be26a5c2dc4e9f3a`.
- **License:** the repository has no LICENSE file. The content is the set of
  examples published in IETF RFC 7049/8949, which fall under the IETF Trust
  Legal Provisions. If a stricter provenance is needed, the same table can be
  rebuilt from the RFC 8949 text.
- **Nature:** synthetic examples, written by hand by the RFC authors.

## Generated at runtime

The tests and `make demo` generate all other key material on the fly: key
pairs, attestation CAs and certificates, credential IDs. Each demo run writes
a temporary SQLite database and deletes it afterwards.
