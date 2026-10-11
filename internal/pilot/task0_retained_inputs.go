package pilot

import (
	"os"
	"sync"
)

// Only the directly owned command.Wait goroutine closes exit. A protocol
// failure, missing role handle or kill request is never a join observation.
func task0DirectJoinCompleted(p *freshPreparationProcess) bool {
	if p == nil || p.exit == nil {
		return false
	}
	select {
	case <-p.exit:
		return true
	default:
		return false
	}
}

type task0RetainedInputOwner struct {
	process *freshPreparationProcess
	release func()
}

var task0PendingInputRetirements = struct {
	sync.Mutex
	changed *sync.Cond
	owners  map[*task0RetainedInputOwner]struct{}
}{owners: make(map[*task0RetainedInputOwner]struct{})}

// The closure keeps the exact held objects reachable on a failed, bounded
// retirement. It runs only after real direct Wait. This never grants a new
// execution or turns an unsuccessful protocol into successful retirement.
func task0RetainInputsUntilDirectJoin(p *freshPreparationProcess, release func()) {
	if release == nil {
		return
	}
	if p == nil {
		release()
		return
	}
	owner := &task0RetainedInputOwner{p, release}
	state := &task0PendingInputRetirements
	state.Lock()
	if state.changed == nil {
		state.changed = sync.NewCond(&state.Mutex)
	}
	state.owners[owner] = struct{}{}
	state.Unlock()
	go func() {
		<-owner.process.exit
		owner.release()
		state.Lock()
		delete(state.owners, owner)
		state.changed.Broadcast()
		state.Unlock()
	}()
}

// A failed fixed Parent/PREP entry cannot exit and implicitly close retained
// inputs while its directly owned namespace is still alive. The caller has
// already revoked the generation and requested its owned child's stop.
func WaitAcceptedTask0InputRetirements() {
	state := &task0PendingInputRetirements
	state.Lock()
	defer state.Unlock()
	for len(state.owners) != 0 {
		state.changed.Wait()
	}
}

func task0CloseInputFiles(files []*os.File) {
	for _, f := range files {
		if f != nil {
			_ = f.Close()
		}
	}
}
