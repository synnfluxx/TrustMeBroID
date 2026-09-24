// Package sl builds slog attributes for values that recur across the service.
//
// The helpers that touch user data deliberately return a reduced form. An
// operator needs to correlate records and recognise an account in a support
// request; they do not need the raw address or the raw token, and production
// logs are copied into places with weaker access control than the database.
package sl

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"
)

// Err renders an error for logging. It tolerates a nil error, which the old
// implementation did not: err.Error() on nil panics inside the logging call.
//
// error_type carries the concrete type so that alerting can distinguish a
// *pq.Error from a context deadline without matching on message text.
func Err(err error) slog.Attr {
	if err == nil {
		return slog.String("error", "")
	}
	return slog.Group("",
		slog.String("error", err.Error()),
		slog.String("error_type", fmt.Sprintf("%T", unwrapAll(err))),
	)
}

// ErrWith is Err plus a sentinel classification, for call sites that already
// know which expected error they matched.
func ErrWith(err error, sentinel error) slog.Attr {
	if err == nil {
		return slog.String("error", "")
	}
	kind := "unexpected"
	if sentinel != nil && errors.Is(err, sentinel) {
		kind = sentinel.Error()
	}
	return slog.Group("",
		slog.String("error", err.Error()),
		slog.String("error_type", fmt.Sprintf("%T", unwrapAll(err))),
		slog.String("error_kind", kind),
	)
}

func unwrapAll(err error) error {
	for {
		next := errors.Unwrap(err)
		if next == nil {
			return err
		}
		err = next
	}
}

// Email masks the local part and keeps the domain. "daniil@icloud.com" becomes
// "d****l@icloud.com": enough to recognise an account in a support thread,
// not enough to harvest addresses out of a log archive.
func Email(addr string) slog.Attr {
	return slog.String("email", MaskEmail(addr))
}

// MaskEmail is Email's value, for embedding in a larger group.
func MaskEmail(addr string) string {
	addr = strings.TrimSpace(addr)
	if addr == "" {
		return ""
	}
	at := strings.LastIndex(addr, "@")
	if at <= 0 {
		return maskTail(addr)
	}
	return maskTail(addr[:at]) + addr[at:]
}

func maskTail(local string) string {
	switch len(local) {
	case 0:
		return ""
	case 1, 2:
		return strings.Repeat("*", len(local))
	default:
		return local[:1] + strings.Repeat("*", len(local)-2) + local[len(local)-1:]
	}
}

// Username is logged in full: it is public within the product and operators
// need it to act on a report.
func Username(name string) slog.Attr { return slog.String("username", name) }

// Token replaces a credential with a stable fingerprint. Two records about the
// same token line up; the token itself cannot be reconstructed from the log.
func Token(key, token string) slog.Attr {
	return slog.String(key+"_fp", Fingerprint(token))
}

// Fingerprint is Token's value.
func Fingerprint(token string) string {
	if token == "" {
		return "empty"
	}
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:8])
}

// Dur reports elapsed time as whole milliseconds under a fixed key, so latency
// can be aggregated without unit guessing.
func Dur(d time.Duration) slog.Attr {
	return slog.Int64("duration_ms", d.Milliseconds())
}

// Since is Dur measured from start.
func Since(start time.Time) slog.Attr { return Dur(time.Since(start)) }

// Email2 masks an address under a caller-chosen key, for records that carry
// more than one address (sender and recipient, for example).
func Email2(key, addr string) slog.Attr {
	return slog.String(key, MaskEmail(addr))
}
