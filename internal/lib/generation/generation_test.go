package generation

import (
	"regexp"
	"testing"
)

var sixDigits = regexp.MustCompile(`^[0-9]{6}$`)

func TestGenerateCodeShape(t *testing.T) {
	for range 200 {
		code, err := GenerateCode()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		// Zero padding matters: a code printed as "4211" is not the code that
		// was stored, and the comparison would never match.
		if !sixDigits.MatchString(code) {
			t.Fatalf("code %q is not six digits", code)
		}
	}
}

func TestGenerateCodeVaries(t *testing.T) {
	seen := map[string]bool{}
	for range 200 {
		code, err := GenerateCode()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		seen[code] = true
	}

	// Collisions are possible in a million, 200 identical values are not.
	if len(seen) < 150 {
		t.Fatalf("only %d distinct codes out of 200", len(seen))
	}
}
