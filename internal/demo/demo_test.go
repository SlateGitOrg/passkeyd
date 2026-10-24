package demo

import (
	"bytes"
	"context"
	"strings"
	"testing"
)

// TestDemoScenario runs the full demo and requires every expectation to hold.
func TestDemoScenario(t *testing.T) {
	var out bytes.Buffer
	sum, err := Run(context.Background(), &out, Options{VectorsPath: "../../testdata/webauthn-l3-vectors.json", WorkDir: t.TempDir()})
	if err != nil {
		t.Fatalf("%v\n%s", err, out.String())
	}
	if sum.Failed != 0 || sum.VectorsOK != 10 || sum.Passed < 25 {
		t.Fatalf("summary %+v\n%s", sum, out.String())
	}
	for _, want := range []string{"origin_mismatch", "sign_count_regression", "clone_warning=1"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("transcript lacks %q\n%s", want, out.String())
		}
	}
}

func TestDemoMissingVectors(t *testing.T) {
	if _, err := Run(context.Background(), &bytes.Buffer{}, Options{VectorsPath: "nope.json", WorkDir: t.TempDir()}); err == nil {
		t.Fatal("expected error")
	}
}
