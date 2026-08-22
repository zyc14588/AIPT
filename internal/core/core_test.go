package core

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

type recorder struct {
	mu     sync.Mutex
	events []string
}

func (r *recorder) add(event string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.events = append(r.events, event)
}

func (r *recorder) snapshot() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.events...)
}

func dependency(name string, record *recorder) Dependency {
	return Dependency{
		Name: name,
		Start: func(context.Context) error {
			record.add("start:" + name)
			return nil
		},
		Ready: func(context.Context) error {
			record.add("ready:" + name)
			return nil
		},
		Stop: func(context.Context) error {
			record.add("stop:" + name)
			return nil
		},
	}
}

func newCore(t *testing.T, dependencies ...Dependency) *Core {
	t.Helper()
	value, err := New(Options{
		Dependencies:    dependencies,
		ShutdownTimeout: 100 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return value
}

func TestStartRunningStopReverseAndDoubleStop(t *testing.T) {
	record := &recorder{}
	value := newCore(t, dependency("one", record), dependency("two", record))
	if value.State() != StateNew || value.Ready() {
		t.Fatalf("initial snapshot = %+v", value.Snapshot())
	}
	if err := value.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if value.State() != StateRunning || !value.Ready() {
		t.Fatalf("running snapshot = %+v", value.Snapshot())
	}
	if err := value.Stop(context.Background()); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	if err := value.Stop(context.Background()); err != nil {
		t.Fatalf("second Stop: %v", err)
	}
	want := []string{
		"start:one",
		"ready:one",
		"start:two",
		"ready:two",
		"stop:two",
		"stop:one",
	}
	if got := record.snapshot(); !equalStrings(got, want) {
		t.Fatalf("events = %v, want %v", got, want)
	}
	if value.State() != StateStopped || value.Ready() {
		t.Fatalf("stopped snapshot = %+v", value.Snapshot())
	}
}

func TestStartFailureStopsEarlierAndNeverStartsLater(t *testing.T) {
	root := errors.New("start root")
	record := &recorder{}
	first := dependency("first", record)
	second := dependency("second", record)
	second.Start = func(context.Context) error {
		record.add("start:second")
		return root
	}
	third := dependency("third", record)
	value := newCore(t, first, second, third)
	err := value.Start(context.Background())
	if !errors.Is(err, ErrDependencyStart) || !errors.Is(err, root) {
		t.Fatalf("Start error = %v", err)
	}
	want := []string{"start:first", "ready:first", "start:second", "stop:first"}
	if got := record.snapshot(); !equalStrings(got, want) {
		t.Fatalf("events = %v, want %v", got, want)
	}
	if value.State() != StateFailed || value.Ready() {
		t.Fatalf("failed snapshot = %+v", value.Snapshot())
	}
}

func TestReadinessFailureStopsCurrentDependency(t *testing.T) {
	root := errors.New("not ready")
	record := &recorder{}
	item := dependency("item", record)
	item.Ready = func(context.Context) error {
		record.add("ready:item")
		return root
	}
	value := newCore(t, item)
	err := value.Start(context.Background())
	if !errors.Is(err, ErrDependencyReady) || !errors.Is(err, root) {
		t.Fatalf("Start error = %v", err)
	}
	want := []string{"start:item", "ready:item", "stop:item"}
	if got := record.snapshot(); !equalStrings(got, want) {
		t.Fatalf("events = %v, want %v", got, want)
	}
}

func TestStartCleanupErrorPreservesRootFailure(t *testing.T) {
	startRoot := errors.New("start root")
	cleanupRoot := errors.New("cleanup root")
	record := &recorder{}
	first := dependency("first", record)
	first.Stop = func(context.Context) error {
		record.add("stop:first")
		return cleanupRoot
	}
	second := dependency("second", record)
	second.Start = func(context.Context) error {
		record.add("start:second")
		return startRoot
	}
	value := newCore(t, first, second)
	err := value.Start(context.Background())
	for _, target := range []error{
		ErrDependencyStart,
		ErrDependencyStop,
		startRoot,
		cleanupRoot,
	} {
		if !errors.Is(err, target) {
			t.Fatalf("Start error %v does not preserve %v", err, target)
		}
	}
	if snapshot := value.Snapshot(); snapshot.State != StateFailed ||
		!equalStrings(snapshot.StartedDependencies, []string{"first"}) {
		t.Fatalf("failed cleanup snapshot = %+v", snapshot)
	}
}

func TestCancelledStartDoesNotStartDependency(t *testing.T) {
	record := &recorder{}
	value := newCore(t, dependency("item", record))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := value.Start(ctx)
	if !errors.Is(err, ErrStartCancelled) || !errors.Is(err, context.Canceled) {
		t.Fatalf("Start error = %v", err)
	}
	if got := record.snapshot(); len(got) != 0 {
		t.Fatalf("cancelled start produced events: %v", got)
	}
	if value.State() != StateFailed {
		t.Fatalf("state = %s, want %s", value.State(), StateFailed)
	}
}

func TestBoundedShutdownAndDependencyErrorPropagation(t *testing.T) {
	record := &recorder{}
	item := dependency("blocked", record)
	item.Stop = func(ctx context.Context) error {
		record.add("stop:blocked")
		<-ctx.Done()
		return ctx.Err()
	}
	value, err := New(Options{
		Dependencies:    []Dependency{item},
		ShutdownTimeout: 20 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := value.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	started := time.Now()
	err = value.Stop(context.Background())
	if elapsed := time.Since(started); elapsed > 500*time.Millisecond {
		t.Fatalf("Stop exceeded bounded window: %v", elapsed)
	}
	if !errors.Is(err, ErrDependencyStop) || !errors.Is(err, ErrShutdownTimeout) ||
		!errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Stop error = %v", err)
	}
	if value.State() != StateFailed || value.Ready() {
		t.Fatalf("failed stop snapshot = %+v", value.Snapshot())
	}
}

func TestStopNewIsIdempotentAndSideEffectFree(t *testing.T) {
	value := newCore(t)
	if err := value.Stop(context.Background()); err != nil {
		t.Fatalf("Stop(new): %v", err)
	}
	if err := value.Stop(context.Background()); err != nil {
		t.Fatalf("Stop(stopped): %v", err)
	}
	if snapshot := value.Snapshot(); snapshot.State != StateStopped || snapshot.Ready ||
		len(snapshot.StartedDependencies) != 0 {
		t.Fatalf("snapshot = %+v", snapshot)
	}
}

func TestStartingAndStoppingStatesAreObservable(t *testing.T) {
	startEntered := make(chan struct{})
	startRelease := make(chan struct{})
	stopEntered := make(chan struct{})
	stopRelease := make(chan struct{})
	item := Dependency{
		Name: "blocking",
		Start: func(context.Context) error {
			close(startEntered)
			<-startRelease
			return nil
		},
		Ready: func(context.Context) error { return nil },
		Stop: func(context.Context) error {
			close(stopEntered)
			<-stopRelease
			return nil
		},
	}
	value := newCore(t, item)
	startResult := make(chan error, 1)
	go func() { startResult <- value.Start(context.Background()) }()
	<-startEntered
	if value.State() != StateStarting || value.Ready() {
		t.Fatalf("starting snapshot = %+v", value.Snapshot())
	}
	close(startRelease)
	if err := <-startResult; err != nil {
		t.Fatalf("Start: %v", err)
	}

	stopResult := make(chan error, 1)
	go func() { stopResult <- value.Stop(context.Background()) }()
	<-stopEntered
	if value.State() != StateStopping || value.Ready() {
		t.Fatalf("stopping snapshot = %+v", value.Snapshot())
	}
	close(stopRelease)
	if err := <-stopResult; err != nil {
		t.Fatalf("Stop: %v", err)
	}
	if value.State() != StateStopped {
		t.Fatalf("state = %s, want %s", value.State(), StateStopped)
	}
}

func TestInvalidTransitionsAndOptions(t *testing.T) {
	if _, err := New(Options{}); !errors.Is(err, ErrInvalidOptions) {
		t.Fatalf("zero timeout error = %v", err)
	}
	record := &recorder{}
	duplicate := dependency("same", record)
	if _, err := New(Options{
		Dependencies:    []Dependency{duplicate, duplicate},
		ShutdownTimeout: time.Second,
	}); !errors.Is(err, ErrInvalidOptions) {
		t.Fatalf("duplicate dependency error = %v", err)
	}
	value := newCore(t)
	if err := value.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if err := value.Start(context.Background()); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("second Start error = %v", err)
	}
}

func TestConcurrentReadersAndSerializedStart(t *testing.T) {
	value := newCore(t)
	var wait sync.WaitGroup
	errs := make(chan error, 2)
	for range 2 {
		wait.Add(1)
		go func() {
			defer wait.Done()
			for range 100 {
				_ = value.State()
				_ = value.Ready()
				_ = value.Snapshot()
			}
			errs <- value.Start(context.Background())
		}()
	}
	wait.Wait()
	close(errs)
	var success, invalid int
	for err := range errs {
		switch {
		case err == nil:
			success++
		case errors.Is(err, ErrInvalidTransition):
			invalid++
		default:
			t.Fatalf("unexpected concurrent Start error: %v", err)
		}
	}
	if success != 1 || invalid != 1 {
		t.Fatalf("success=%d invalid=%d", success, invalid)
	}
}

func equalStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}
