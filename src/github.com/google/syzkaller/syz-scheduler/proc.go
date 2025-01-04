package main

import (
	"bytes"
	"fmt"
	"math/rand"
	"os"
	"runtime/debug"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/google/syzkaller/pkg/common"
	"github.com/google/syzkaller/pkg/cover"
	"github.com/google/syzkaller/pkg/hash"
	"github.com/google/syzkaller/pkg/ipc"
	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/pkg/rpctype"
	"github.com/google/syzkaller/pkg/signal"
	"github.com/google/syzkaller/prog"
	"github.com/google/syzkaller/uaf"
)

type Proc struct {
	scheduler            *Scheduler
	pid                  int
	env                  *ipc.Env
	rnd                  *rand.Rand
	execOpts             *ipc.ExecOpts // collide & ^cover
	execOptsCover        *ipc.ExecOpts // ^collide & cover
	execOptsComps        *ipc.ExecOpts //
	execOptsNoCollide    *ipc.ExecOpts // ^collide & ^cover
	execOptsCollideCover *ipc.ExecOpts // collide & cover
}

func newProc(scheduler *Scheduler, pid int) (*Proc, error) {
	env, err := ipc.MakeEnv(scheduler.config, pid)
	if err != nil {
		return nil, err
	}
	rnd := rand.New(rand.NewSource(time.Now().UnixNano() + int64(pid)*1e12))
	execOptsNoCollide := *scheduler.execOpts
	execOptsNoCollide.Flags &= ^ipc.FlagCollide
	execOptsNoCollide.Flags &= ^ipc.FlagThreaded
	execOptsCover := execOptsNoCollide
	execOptsCover.Flags |= ipc.FlagCollectCover
	execOptsComps := execOptsNoCollide
	execOptsComps.Flags |= ipc.FlagCollectComps
	execOptsCollideCover := *scheduler.execOpts
	execOptsCollideCover.Flags |= ipc.FlagCollectCover
	proc := &Proc{
		scheduler:            scheduler,
		pid:                  pid,
		env:                  env,
		rnd:                  rnd,
		execOpts:             scheduler.execOpts,
		execOptsCover:        &execOptsCover,
		execOptsComps:        &execOptsComps,
		execOptsNoCollide:    &execOptsNoCollide,
		execOptsCollideCover: &execOptsCollideCover,
	}
	return proc, nil
}

func (proc *Proc) loop() {
	for i := 0; ; i++ {
		item := proc.scheduler.workQueue.dequeue()
		if item != nil {
			switch item := item.(type) {
			case *WorkTriage:
				proc.triageInput(item)
			case *WorkCandidate:
				proc.execute(proc.execOpts, item.p, item.flags, StatCandidate, false, item.UafInfo)
			case *WorkSmash:
				proc.smashInput(item)
			default:
				log.Fatalf("unknown work type: %#v", item)
			}
			continue
		}

		ct := proc.scheduler.choiceTable
		evState := proc.scheduler.evState
		fuzzerSnapshot := proc.scheduler.snapshot()

		// Mutate an existing prog.
		u := fuzzerSnapshot.chooseProgram(proc.rnd)
		p := u.Prog.Clone()
		idx := p.MutateUaf(proc.rnd, prog.RecommendedCalls, ct, ExtractProgs(fuzzerSnapshot.corpus), evState, [2]int{u.FreeIndex, u.UseIndex})
		u.FreeIndex = idx[0]
		u.UseIndex = idx[1]
		log.Logf(1, "#%v: mutated", proc.pid)
		proc.execute(proc.execOpts, p, ProgNormal, StatFuzz, true, u.UafInfo)
	}
}

func (proc *Proc) triageInput(item *WorkTriage) {
	log.Logf(1, "#%v: triaging type=%x", proc.pid, item.flags)

	prio := signalPrio(item.p, &item.info, item.call)
	inputSignal := signal.FromRaw(item.info.Signal, prio)
	newSignal := proc.scheduler.corpusSignalDiff(inputSignal)
	if newSignal.Empty() {
		return
	}
	callName := ".extra"
	logCallName := "extra"
	if item.call != -1 {
		callName = item.p.Calls[item.call].Meta.Name
		logCallName = fmt.Sprintf("call #%v %v", item.call, callName)
	}
	log.Logf(3, "triaging input for %v (new signal=%v)", logCallName, newSignal.Len())
	var inputCover cover.Cover
	const (
		signalRuns       = 3
		minimizeAttempts = 3
	)
	// Compute input coverage and non-flaky signal for minimization.
	notexecuted := 0
	rawCover := []uint32{}
	for i := 0; i < signalRuns; i++ {
		info := proc.executeRaw(proc.execOptsCover, item.p, StatTriage, item.UafInfo)
		if !reexecutionSuccess(info, &item.info, item.call) {
			// The call was not executed or failed.
			notexecuted++
			if notexecuted > signalRuns/2+1 {
				return // if happens too often, give up
			}
			continue
		}
		thisSignal, thisCover := getSignalAndCover(item.p, info, item.call)
		if len(rawCover) == 0 && proc.scheduler.fetchRawCover {
			rawCover = append([]uint32{}, thisCover...)
		}
		newSignal = newSignal.Intersection(thisSignal)
		// Without !minimized check manager starts losing some considerable amount
		// of coverage after each restart. Mechanics of this are not completely clear.
		if newSignal.Empty() && item.flags&ProgMinimized == 0 {
			return
		}
		inputCover.Merge(thisCover)
	}
	if item.flags&ProgMinimized == 0 {
		var idx [2]int
		item.p, item.call, idx = prog.MinimizeUaf(item.p, item.call, false,
			func(p1 *prog.Prog, call1 int, index [2]int) bool {
				for i := 0; i < minimizeAttempts; i++ {
					uafInfo := item.UafInfo
					uafInfo.FreeIndex = index[0]
					uafInfo.UseIndex = index[1]
					info := proc.execute(proc.execOpts, p1, ProgNormal, StatMinimize, false, uafInfo)
					if !reexecutionSuccess(info, &item.info, call1) {
						// The call was not executed or failed.
						continue
					}
					thisSignal, _ := getSignalAndCover(p1, info, call1)
					if newSignal.Intersection(thisSignal).Len() == newSignal.Len() {
						return true
					}
				}
				return false
			}, [2]int{item.UafInfo.FreeIndex, item.UafInfo.UseIndex})
		item.UafInfo.FreeIndex = idx[0]
		item.UafInfo.UseIndex = idx[1]
	}

	data := item.p.Serialize()
	sig := hash.Hash(data, item.UafInfo.Serialize())

	log.Logf(2, "added new input for %v to corpus:\n%s", logCallName, data)
	proc.scheduler.sendInputToManager(rpctype.UafInput{
		Call:     callName,
		CallID:   item.call,
		Prog:     data,
		Signal:   inputSignal.Serialize(),
		Cover:    inputCover.Serialize(),
		RawCover: rawCover,
		UafInfo:  item.UafInfo,
	})

	proc.scheduler.addInputToCorpus(&uaf.UafCandiate{
		Prog:    item.p,
		UafInfo: item.UafInfo,
	}, inputSignal, sig)

	if item.flags&ProgSmashed == 0 {
		proc.scheduler.workQueue.enqueue(&WorkSmash{item.p, item.call, item.UafInfo})
	}
}

func getSignalAndCover(p *prog.Prog, info *ipc.ProgInfo, call int) (signal.Signal, []uint32) {
	inf := &info.Extra
	if call != -1 {
		inf = &info.Calls[call]
	}
	return signal.FromRaw(inf.Signal, signalPrio(p, inf, call)), inf.Cover
}

func reexecutionSuccess(info *ipc.ProgInfo, oldInfo *ipc.CallInfo, call int) bool {
	if info == nil || len(info.Calls) == 0 {
		return false
	}
	if call != -1 {
		// Don't minimize calls from successful to unsuccessful.
		// Successful calls are much more valuable.
		if oldInfo.Errno == 0 && info.Calls[call].Errno != 0 {
			return false
		}
		return len(info.Calls[call].Signal) != 0
	}
	return len(info.Extra.Signal) != 0
}

func (proc *Proc) execute(execOpts *ipc.ExecOpts, p *prog.Prog, flags ProgTypes, stat Stat, keepEvts bool, uafInfo common.UafInfo) *ipc.ProgInfo {
	info := proc.executeRaw(execOpts, p, stat, uafInfo)
	if info == nil {
		return nil
	}
	calls, extra := proc.scheduler.checkNewSignal(p, info)
	for _, callIndex := range calls {
		proc.enqueueCallTriage(p, flags, callIndex, info.Calls[callIndex], uafInfo)
	}
	if extra {
		proc.enqueueCallTriage(p, flags, -1, info.Extra, uafInfo)
	}
	if keepEvts {
		proc.scheduler.checkNewEvents(p, info)
	}
	return info
}

func (proc *Proc) enqueueCallTriage(p *prog.Prog, flags ProgTypes, callIndex int, info ipc.CallInfo, uafInfo common.UafInfo) {
	// info.Signal points to the output shmem region, detach it before queueing.
	info.Signal = append([]uint32{}, info.Signal...)
	// None of the caller use Cover, so just nil it instead of detaching.
	// Note: triage input uses executeRaw to get coverage.
	info.Cover = nil
	proc.scheduler.workQueue.enqueue(&WorkTriage{
		p:       p.Clone(),
		call:    callIndex,
		info:    info,
		flags:   flags,
		UafInfo: uafInfo,
	})
}

func (proc *Proc) smashInput(item *WorkSmash) {

}

func (proc *Proc) executeRaw(opts *ipc.ExecOpts, p *prog.Prog, stat Stat, uafInfo common.UafInfo) *ipc.ProgInfo {
	proc.scheduler.checkDisabledCalls(p)

	// Limit concurrency window and do leak checking once in a while.
	ticket := proc.scheduler.gate.Enter()
	defer proc.scheduler.gate.Leave(ticket)

	proc.logProgram(opts, p, uafInfo)
	for try := 0; ; try++ {
		atomic.AddUint64(&proc.scheduler.stats[stat], 1)
		output, info, hanged, err := proc.env.ExecUaf(opts, p, uafInfo)
		if err != nil {
			if err == prog.ErrExecBufferTooSmall {
				// It's bad if we systematically fail to serialize programs,
				// but so far we don't have a better handling than ignoring this.
				// This error is observed a lot on the seeded syz_mount_image calls.
				return nil
			}
			if try > 10 {
				log.Fatalf("executor %v failed %v times: %v", proc.pid, try, err)
			}
			log.Logf(4, "fuzzer detected executor failure='%v', retrying #%d", err, try+1)
			debug.FreeOSMemory()
			time.Sleep(time.Second)
			continue
		}
		log.Logf(2, "result hanged=%v: %s", hanged, output)
		return info
	}
}

func (proc *Proc) logProgram(opts *ipc.ExecOpts, p *prog.Prog, uafInfo common.UafInfo) {
	if proc.scheduler.outputType == OutputNone {
		return
	}

	data := p.Serialize()
	info := uafInfo.Serialize()

	// The following output helps to understand what program crashed kernel.
	// It must not be intermixed.
	switch proc.scheduler.outputType {
	case OutputStdout:
		now := time.Now()
		proc.scheduler.logMu.Lock()
		fmt.Printf("%02v:%02v:%02v executing program %v:\n%s\n%s\n",
			now.Hour(), now.Minute(), now.Second(),
			proc.pid, data, info)
		proc.scheduler.logMu.Unlock()
	case OutputDmesg:
		fd, err := syscall.Open("/dev/kmsg", syscall.O_WRONLY, 0)
		if err == nil {
			buf := new(bytes.Buffer)
			fmt.Fprintf(buf, "syzkaller: executing program %v:\n%s\n%s\n",
				proc.pid, data, info)
			syscall.Write(fd, buf.Bytes())
			syscall.Close(fd)
		}
	case OutputFile:
		f, err := os.Create(fmt.Sprintf("%v-%v.prog", proc.scheduler.name, proc.pid))
		if err == nil {
			f.Write(data)
			f.Write(info)
			f.Close()
		}
	default:
		log.Fatalf("unknown output type: %v", proc.scheduler.outputType)
	}
}
