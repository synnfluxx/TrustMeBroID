package sl

import (
	"errors"
	"fmt"
	"log/slog"
	"testing"
	"time"
)

func TestErr_NilIsSafe(t *testing.T) {
	// The previous implementation called err.Error() unconditionally, so
	// logging a nil error panicked inside the logging call.
	attr := Err(nil)
	if attr.Value.String() != "" {
		t.Fatalf("Err(nil) = %v, want an empty value", attr.Value)
	}
}

func TestErr_CarriesMessageAndUnwrappedType(t *testing.T) {
	base := errors.New("boom")
	wrapped := fmt.Errorf("outer: %w", fmt.Errorf("inner: %w", base))

	group := Err(wrapped).Value.Group()

	var message, kind string
	for _, a := range group {
		switch a.Key {
		case "error":
			message = a.Value.String()
		case "error_type":
			kind = a.Value.String()
		}
	}

	if message != "outer: inner: boom" {
		t.Fatalf("error = %q", message)
	}
	// The type is taken from the innermost cause, not the fmt wrapper.
	if kind != "*errors.errorString" {
		t.Fatalf("error_type = %q", kind)
	}
}

func TestErrWith_ClassifiesAgainstASentinel(t *testing.T) {
	sentinel := errors.New("user not found")
	wrapped := fmt.Errorf("lookup: %w", sentinel)

	find := func(attr slog.Attr, key string) string {
		for _, a := range attr.Value.Group() {
			if a.Key == key {
				return a.Value.String()
			}
		}
		return ""
	}

	if got := find(ErrWith(wrapped, sentinel), "error_kind"); got != "user not found" {
		t.Fatalf("error_kind = %q, want the sentinel text", got)
	}
	if got := find(ErrWith(wrapped, errors.New("other")), "error_kind"); got != "unexpected" {
		t.Fatalf("error_kind = %q, want unexpected", got)
	}
	if ErrWith(nil, sentinel).Value.String() != "" {
		t.Fatal("ErrWith(nil) should produce an empty value")
	}
}

func TestMaskEmail(t *testing.T) {
	cases := map[string]string{
		"daniil@icloud.com": "d****l@icloud.com",
		"ab@example.com":    "**@example.com",
		"a@example.com":     "*@example.com",
		"  padded@x.io  ":   "p****d@x.io",
		"no-at-sign":        "n********n",
		"":                  "",
		// Split is on the last "@", so the local part here is "a@b".
		"a@b@c.com": "a*b@c.com",
	}
	for in, want := range cases {
		if got := MaskEmail(in); got != want {
			t.Fatalf("MaskEmail(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestMaskEmail_NeverLeaksTheLocalPart(t *testing.T) {
	const addr = "verysecretlocalpart@example.com"
	masked := MaskEmail(addr)

	if masked == addr {
		t.Fatal("address was not masked")
	}
	if len(masked) != len(addr) {
		t.Fatalf("masking changed the length: %q", masked)
	}
}

func TestEmailAttrs(t *testing.T) {
	if Email("daniil@icloud.com").Key != "email" {
		t.Fatal("Email should use the key \"email\"")
	}
	attr := Email2("smtp_from", "noreply@auralift.test")
	if attr.Key != "smtp_from" {
		t.Fatalf("Email2 key = %q", attr.Key)
	}
	if attr.Value.String() != "n*****y@auralift.test" {
		t.Fatalf("Email2 value = %q", attr.Value.String())
	}
}

func TestFingerprint(t *testing.T) {
	const token = "a-refresh-token"

	first, second := Fingerprint(token), Fingerprint(token)
	if first != second {
		t.Fatal("fingerprint is not stable")
	}
	if len(first) != 16 {
		t.Fatalf("fingerprint length = %d, want 16", len(first))
	}
	if first == token {
		t.Fatal("fingerprint must not be the token")
	}
	if Fingerprint("another-token") == first {
		t.Fatal("different tokens must fingerprint differently")
	}
	if Fingerprint("") != "empty" {
		t.Fatal("an empty token should fingerprint as \"empty\"")
	}
}

func TestTokenAttrKey(t *testing.T) {
	attr := Token("refresh", "a-token")
	if attr.Key != "refresh_fp" {
		t.Fatalf("key = %q, want refresh_fp", attr.Key)
	}
	if attr.Value.String() == "a-token" {
		t.Fatal("the raw token must not be the value")
	}
}

func TestUsernameIsNotMasked(t *testing.T) {
	// Usernames are public within the product and operators act on them.
	if Username("octocat").Value.String() != "octocat" {
		t.Fatal("username should be logged verbatim")
	}
}

func TestDurAndSince(t *testing.T) {
	attr := Dur(1500 * time.Millisecond)
	if attr.Key != "duration_ms" {
		t.Fatalf("key = %q", attr.Key)
	}
	if attr.Value.Int64() != 1500 {
		t.Fatalf("value = %d, want 1500", attr.Value.Int64())
	}

	if Since(time.Now().Add(-2*time.Second)).Value.Int64() < 1900 {
		t.Fatal("Since should measure elapsed time")
	}
}
