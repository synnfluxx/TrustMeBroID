package app

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	discardHandler "github.com/synnfluxx/TrustMeBroID/internal/lib/logger/handlers/discardHandler"
)

// fakeReaper stands in for the storage reaper so the background loop can be
// exercised without a database.
type fakeReaper struct {
	mu      sync.Mutex
	calls   atomic.Int64
	deleted []int64
	err     error
}

func (f *fakeReaper) Reaper(context.Context) ([]int64, error) {
	f.calls.Add(1)
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.deleted, f.err
}

func TestStartReaper_RunsOnTheInterval(t *testing.T) {
	fake := &fakeReaper{deleted: []int64{1, 2}}

	cancel := startReaperLoop(t.Context(), discardHandler.NewDiscardLogger(), fake, 10*time.Millisecond)
	defer cancel()

	require.Eventually(t, func() bool { return fake.calls.Load() >= 3 },
		2*time.Second, 10*time.Millisecond, "the reaper did not run repeatedly")
}

func TestStartReaper_KeepsRunningAfterAFailure(t *testing.T) {
	// A transient database error must not kill the loop: the next tick has to
	// try again, otherwise deleted users accumulate silently forever.
	fake := &fakeReaper{err: errors.New("connection refused")}

	cancel := startReaperLoop(t.Context(), discardHandler.NewDiscardLogger(), fake, 10*time.Millisecond)
	defer cancel()

	require.Eventually(t, func() bool { return fake.calls.Load() >= 3 },
		2*time.Second, 10*time.Millisecond, "the loop stopped after an error")
}

func TestStartReaper_StopsOnCancel(t *testing.T) {
	fake := &fakeReaper{}
	ctx, cancel := context.WithCancel(context.Background())

	stop := startReaperLoop(ctx, discardHandler.NewDiscardLogger(), fake, 10*time.Millisecond)
	defer stop()

	require.Eventually(t, func() bool { return fake.calls.Load() >= 1 },
		2*time.Second, 10*time.Millisecond)

	cancel()
	settled := fake.calls.Load()
	time.Sleep(60 * time.Millisecond)

	require.LessOrEqual(t, fake.calls.Load(), settled+1, "the loop kept ticking after cancellation")
}
