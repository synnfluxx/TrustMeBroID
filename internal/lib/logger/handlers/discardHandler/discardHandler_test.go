package discardHandler

import (
	"context"
	"log/slog"
	"testing"
)

func TestDiscardHandler_IsAlwaysDisabled(t *testing.T) {
	h := NewDiscardHandler()

	for _, level := range []slog.Level{slog.LevelDebug, slog.LevelInfo, slog.LevelWarn, slog.LevelError} {
		if h.Enabled(context.Background(), level) {
			t.Fatalf("handler reported %v as enabled", level)
		}
	}
}

func TestDiscardHandler_SwallowsRecords(t *testing.T) {
	h := NewDiscardHandler()

	if err := h.Handle(context.Background(), slog.Record{}); err != nil {
		t.Fatalf("Handle returned %v", err)
	}
}

func TestDiscardHandler_WithAttrsAndGroupReturnItself(t *testing.T) {
	h := NewDiscardHandler()

	if h.WithAttrs([]slog.Attr{slog.String("k", "v")}) != h {
		t.Fatal("WithAttrs should return the same handler")
	}
	if h.WithGroup("g") != h {
		t.Fatal("WithGroup should return the same handler")
	}
}

// Tests use this logger everywhere; it must never panic on a real call.
func TestNewDiscardLogger_IsUsable(t *testing.T) {
	log := NewDiscardLogger()
	if log == nil {
		t.Fatal("NewDiscardLogger returned nil")
	}

	log.Info("nothing should happen", slog.Int("n", 1))
	log.With(slog.String("op", "test")).Error("still nothing")
}
