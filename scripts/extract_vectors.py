#!/usr/bin/env python3
"""Extract the WebAuthn Level 3 "Test Vectors" section (sec. 16) into JSON.

Usage: python3 scripts/extract_vectors.py <webauthn-spec.html> > internal/vectors/testdata/webauthn-l3.json

Only the stdlib is used. Each subsection becomes an object with "registration"
and "authentication" maps of name -> lowercase hex string, exactly as printed
in the spec's CDDL pseudocode (h'...').
"""
import html
import json
import re
import sys

SECTIONS = [
    "attestation-root-cert",
    "none-es256",
    "packed-self-es256",
    "none-es256-crossOrigin",
    "none-es256-topOrigin",
    "none-es256-long-credential-id",
    "packed-es256",
    "packed-es384",
    "packed-es512",
    "packed-rs256",
    "packed-eddsa",
    "packed-ed448",
]

ASSIGN = re.compile(r"^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*h'([0-9a-fA-F]*)'", re.M)


def section_text(doc: str, sid: str) -> str:
    start = doc.index(f'id="sctn-test-vectors-{sid}"')
    nxt = doc.find('id="sctn-test-vectors-', start + 10)
    seg = doc[start: nxt if nxt != -1 else len(doc)]
    return html.unescape(re.sub(r"<[^>]+>", "", seg))


def parse(text: str) -> dict:
    out = {"registration": {}, "authentication": {}}
    phase = "registration"
    for line in text.splitlines():
        if line.strip().startswith("Authentication:"):
            phase = "authentication"
            continue
        m = ASSIGN.match(line)
        if m:
            out[phase][m.group(1)] = m.group(2).lower()
    return out


def main() -> None:
    doc = open(sys.argv[1], encoding="utf-8").read()
    result = {
        "source": "https://w3c.github.io/webauthn/#sctn-test-vectors",
        "license": "W3C Software and Document License",
        "vectors": {sid: parse(section_text(doc, sid)) for sid in SECTIONS},
    }
    json.dump(result, sys.stdout, indent=1, sort_keys=True)
    sys.stdout.write("\n")


if __name__ == "__main__":
    main()
