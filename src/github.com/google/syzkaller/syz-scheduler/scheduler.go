package main

import (
	"bytes"
	"encoding/binary"
	"encoding/gob"
	"flag"
	"fmt"
	"math/rand"
	"os"
	"runtime"
	"runtime/debug"
	"sort"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/google/syzkaller/pkg/csource"
	"github.com/google/syzkaller/pkg/evtrack"
	"github.com/google/syzkaller/pkg/hash"
	"github.com/google/syzkaller/pkg/host"
	"github.com/google/syzkaller/pkg/ipc"
	"github.com/google/syzkaller/pkg/ipc/ipcconfig"
	"github.com/google/syzkaller/pkg/ivshmem"
	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/pkg/rpctype"
	"github.com/google/syzkaller/pkg/signal"
	"github.com/google/syzkaller/pkg/tool"
	"github.com/google/syzkaller/prog"
	"github.com/google/syzkaller/sys/targets"
	"github.com/google/syzkaller/uaf"
)

type Scheduler struct {
	name              string
	outputType        OutputType
	config            *ipc.Config
	execOpts          *ipc.ExecOpts
	procs             []*Proc
	gate              *ipc.Gate
	workQueue         *WorkQueue
	needPoll          chan struct{}
	choiceTable       *prog.ChoiceTable
	stats             [StatCount]uint64
	manager           *rpctype.RPCClient
	target            *prog.Target
	calls             map[*prog.Syscall]bool
	triagedCandidates uint32
	timeouts          targets.Timeouts

	faultInjectionEnabled    bool
	comparisonTracingEnabled bool
	fetchRawCover            bool

	corpusMu     sync.RWMutex
	corpus       []*uaf.UafCandiate
	corpusHashes map[hash.Sig]struct{}
	corpusPrios  []int64
	sumPrios     int64

	signalMu     sync.RWMutex
	corpusSignal signal.Signal      // signal of inputs in corpus
	maxSignal    signal.Signal      // max signal ever observed including flakes
	newSignal    signal.Signal      // diff of maxSignal since last sync with master
	evState      *prog.EvTrackState // state of evtrack, groups and choice table
	eventsMu     sync.RWMutex
	batches      []prog.Batch
	hasBatch     chan bool
	numEvents    uint64
	evDropRate   int
	vanilla      bool
	banned       map[string]bool
	deletedIDs   []uint64

	checkResult *rpctype.CheckArgs
	logMu       sync.Mutex
	ivshmem     []byte
}

type OutputType int

const (
	OutputNone OutputType = iota
	OutputStdout
	OutputDmesg
	OutputFile
)

type Stat int

const (
	StatFuzz Stat = iota
	StatCandidate
	StatTriage
	StatMinimize
	StatSmash
	StatHint
	StatSeed
	StatCount
)

type FuzzerSnapshot struct {
	corpus      []*uaf.UafCandiate
	corpusPrios []int64
	sumPrios    int64
}

var statNames = [StatCount]string{
	StatFuzz:      "exec fuzz",
	StatCandidate: "exec candidate",
	StatTriage:    "exec triage",
	StatMinimize:  "exec minimize",
	StatSmash:     "exec smash",
	StatHint:      "exec hints",
	StatSeed:      "exec seeds",
}

func createIPCConfig(features *host.Features, config *ipc.Config) {
	if features[host.FeatureExtraCoverage].Enabled {
		config.Flags |= ipc.FlagExtraCover
	}
	if features[host.FeatureDelayKcovMmap].Enabled {
		config.Flags |= ipc.FlagDelayKcovMmap
	}
	if features[host.FeatureNetInjection].Enabled {
		config.Flags |= ipc.FlagEnableTun
	}
	if features[host.FeatureNetDevices].Enabled {
		config.Flags |= ipc.FlagEnableNetDev
	}
	config.Flags |= ipc.FlagEnableNetReset
	config.Flags |= ipc.FlagEnableCgroups
	config.Flags |= ipc.FlagEnableCloseFds
	if features[host.FeatureDevlinkPCI].Enabled {
		config.Flags |= ipc.FlagEnableDevlinkPCI
	}
	if features[host.FeatureVhciInjection].Enabled {
		config.Flags |= ipc.FlagEnableVhciInjection
	}
	if features[host.FeatureWifiEmulation].Enabled {
		config.Flags |= ipc.FlagEnableWifi
	}
}

// nolint: funlen
func main() {

	// gob requires registration of interface types
	gob.RegisterName("github.com/google/syzkaller/prog.PointerArg", &prog.PointerArg{})
	gob.RegisterName("github.com/google/syzkaller/prog.ResultArg", &prog.ResultArg{})
	gob.RegisterName("github.com/google/syzkaller/prog.GroupArg", &prog.GroupArg{})
	gob.RegisterName("github.com/google/syzkaller/prog.DataArg", &prog.DataArg{})
	gob.RegisterName("github.com/google/syzkaller/prog.ConstArg", &prog.ConstArg{})
	gob.RegisterName("github.com/google/syzkaller/prog.UnionArg", &prog.UnionArg{})

	debug.SetGCPercent(50)

	var (
		flagName     = flag.String("name", "test", "unique name for manager")
		flagOS       = flag.String("os", runtime.GOOS, "target OS")
		flagArch     = flag.String("arch", runtime.GOARCH, "target arch")
		flagManager  = flag.String("manager", "", "manager rpc address")
		flagProcs    = flag.Int("procs", 1, "number of parallel test processes")
		flagOutput   = flag.String("output", "stdout", "write programs to none/stdout/dmesg/file")
		flagRawCover = flag.Bool("raw_cover", false, "fetch raw coverage")
		flagVanilla  = flag.Bool("vanilla", false, "use vanilla call generation exclusively")
	)
	defer tool.Init()()
	outputType := parseOutputType(*flagOutput)
	log.Logf(0, "fuzzer started (pid=%v)", syscall.Getpid())

	target, err := prog.GetTarget(*flagOS, *flagArch)
	if err != nil {
		log.Fatalf("%v", err)
	}

	config, execOpts, err := ipcconfig.Default(target)
	if err != nil {
		log.Fatalf("failed to create default ipc config: %v", err)
	}
	if *flagRawCover {
		execOpts.Flags &^= ipc.FlagDedupCover
	}
	timeouts := config.Timeouts
	sandbox := ipc.FlagsToSandbox(config.Flags)
	shutdown := make(chan struct{})
	osutil.HandleInterrupts(shutdown)
	go func() {
		// Handles graceful preemption on GCE.
		<-shutdown
		log.Logf(0, "SYZ-FUZZER: PREEMPTED")
		os.Exit(1)
	}()

	checkArgs := &checkArgs{
		target:         target,
		sandbox:        sandbox,
		ipcConfig:      config,
		ipcExecOpts:    execOpts,
		gitRevision:    prog.GitRevision,
		targetRevision: target.Revision,
	}

	machineInfo, modules := collectMachineInfos(target)

	log.Logf(0, "dialing manager at %v", *flagManager)
	manager, err := rpctype.NewRPCClient(*flagManager, timeouts.Scale)
	if err != nil {
		log.Fatalf("failed to connect to manager: %v ", err)
	}

	log.Logf(1, "connecting to manager...")
	a := &rpctype.ConnectArgs{
		Name:        *flagName,
		MachineInfo: machineInfo,
		Modules:     modules,
	}
	r := &rpctype.ConnectRes{}
	if err := manager.Call("Manager.SchedulerConnect", a, r); err != nil {
		log.Fatalf("failed to connect to manager: %v ", err)
	}
	featureFlags, err := csource.ParseFeaturesFlags("none", "none", true)
	if err != nil {
		log.Fatal(err)
	}
	if r.CoverFilterBitmap != nil {
		if err := osutil.WriteFile("syz-cover-bitmap", r.CoverFilterBitmap); err != nil {
			log.Fatalf("failed to write syz-cover-bitmap: %v", err)
		}
	}
	if r.CheckResult == nil {
		checkArgs.gitRevision = r.GitRevision
		checkArgs.targetRevision = r.TargetRevision
		checkArgs.enabledCalls = r.EnabledCalls
		checkArgs.allSandboxes = r.AllSandboxes
		checkArgs.featureFlags = featureFlags
		r.CheckResult, err = checkMachine(checkArgs)
		if err != nil {
			if r.CheckResult == nil {
				r.CheckResult = new(rpctype.CheckArgs)
			}
			r.CheckResult.Error = err.Error()
		}
		r.CheckResult.Name = *flagName
		if err := manager.Call("Manager.Check", r.CheckResult, nil); err != nil {
			log.Fatalf("Manager.Check call failed: %v", err)
		}
		if r.CheckResult.Error != "" {
			log.Fatalf("%v", r.CheckResult.Error)
		}
	} else {
		target.UpdateGlobs(r.CheckResult.GlobFiles)
		if err = host.Setup(target, r.CheckResult.Features, featureFlags, config.Executor); err != nil {
			log.Fatal(err)
		}
	}
	log.Logf(0, "syscalls: %v", len(r.CheckResult.EnabledCalls[sandbox]))
	for _, feat := range r.CheckResult.Features.Supported() {
		log.Logf(0, "%v: %v", feat.Name, feat.Reason)
	}
	createIPCConfig(r.CheckResult.Features, config)

	calls := make(map[*prog.Syscall]bool)
	for _, id := range r.CheckResult.EnabledCalls[sandbox] {
		calls[target.Syscalls[id]] = true
	}

	needPoll := make(chan struct{}, 1)
	needPoll <- struct{}{}
	hasBatch := make(chan bool, 800)
	scheduler := &Scheduler{
		name:                     *flagName,
		outputType:               outputType,
		config:                   config,
		execOpts:                 execOpts,
		workQueue:                newWorkQueue(*flagProcs, needPoll),
		needPoll:                 needPoll,
		manager:                  manager,
		target:                   target,
		calls:                    calls,
		timeouts:                 timeouts,
		faultInjectionEnabled:    r.CheckResult.Features[host.FeatureFault].Enabled,
		comparisonTracingEnabled: r.CheckResult.Features[host.FeatureComparisons].Enabled,
		corpusHashes:             make(map[hash.Sig]struct{}),
		checkResult:              r.CheckResult,
		fetchRawCover:            *flagRawCover,
		evState:                  prog.InitEvTrackState(),
		hasBatch:                 hasBatch,
		vanilla:                  *flagVanilla,
		banned:                   make(map[string]bool),
	}
	gateCallback := scheduler.useBugFrames(r, *flagProcs)
	scheduler.gate = ipc.NewGate(2**flagProcs, gateCallback)

	scheduler.banned["lsetxattr$security_selinux"] = true
	scheduler.banned["openat"] = true
	scheduler.banned["mount"] = true
	scheduler.banned["chown"] = true
	scheduler.banned["ioctl$BLKTRACESETUP"] = true
	scheduler.banned["add_key$keyring"] = true
	scheduler.banned["openat$procfs"] = true
	scheduler.banned["ioctl$sock_SIOCGIFINDEX_80211"] = true
	scheduler.banned["syz_mount_image$tmpfs"] = true
	scheduler.banned["syz_clone3"] = true
	scheduler.banned["syz_mount_image$iso9660"] = true
	scheduler.banned["syz_mount_image$vfat"] = true
	scheduler.banned["syz_mount_image$ext4"] = true
	scheduler.banned["syz_open_dev$sg"] = true

	// initialize shared memory
	err = ivshmem.Load_module("/root/uio.ko")
	if err != nil {
		fmt.Println(err)
		panic("load failed: uio.ko")
	}
	err = ivshmem.Load_module("/root/uio_ivshmem.ko")
	if err != nil {
		fmt.Println(err)
		panic("load failed: uio_ivshmem.ko")
	}
	scheduler.ivshmem, err = ivshmem.GetSharedMappingGuest("/dev/uio0")
	if err != nil {
		fmt.Println(err)
		panic("mmap failed")
	}

	go scheduler.updateEvDropRate()

	for needCandidates, more := true, true; more; needCandidates = false {
		more = scheduler.pollNew(needCandidates, nil, false)
		// This loop lead to "no output" in qemu emulation, tell manager we are not dead.
		log.Logf(0, "fetching corpus: %v, signal %v/%v (executing program)",
			len(scheduler.corpus), len(scheduler.corpusSignal), len(scheduler.maxSignal))
	}
	scheduler.choiceTable = target.BuildChoiceTable(ExtractProgs(scheduler.corpus), calls)
	scheduler.evState.BuildEvChoiceTable(target, calls)

	// get additional strategies from the host
	scheduler.getStrategies()

	if r.CoverFilterBitmap != nil {
		scheduler.execOpts.Flags |= ipc.FlagEnableCoverageFilter
	}

	log.Logf(0, "starting %v fuzzer processes", *flagProcs)
	for pid := 0; pid < *flagProcs; pid++ {
		proc, err := newProc(scheduler, pid)
		if err != nil {
			log.Fatalf("failed to create proc: %v", err)
		}
		scheduler.procs = append(scheduler.procs, proc)
		go proc.loop()
	}

	scheduler.pollLoop()
}

func ExtractProgs(corpus []*uaf.UafCandiate) []*prog.Prog {
	progs := make([]*prog.Prog, len(corpus))
	for i, c := range corpus {
		progs[i] = c.Prog
	}
	return progs

}

func parseOutputType(str string) OutputType {
	switch str {
	case "none":
		return OutputNone
	case "stdout":
		return OutputStdout
	case "dmesg":
		return OutputDmesg
	case "file":
		return OutputFile
	default:
		log.Fatalf("-output flag must be one of none/stdout/dmesg/file")
		return OutputNone
	}
}

func collectMachineInfos(target *prog.Target) ([]byte, []host.KernelModule) {
	machineInfo, err := host.CollectMachineInfo()
	if err != nil {
		log.Fatalf("failed to collect machine information: %v", err)
	}
	modules, err := host.CollectModulesInfo()
	if err != nil {
		log.Fatalf("failed to collect modules info: %v", err)
	}
	return machineInfo, modules
}

// Returns gateCallback for leak checking if enabled.
func (scheduler *Scheduler) useBugFrames(r *rpctype.ConnectRes, flagProcs int) func() {
	var gateCallback func()

	if r.CheckResult.Features[host.FeatureLeak].Enabled {
		gateCallback = func() { scheduler.gateCallback(r.MemoryLeakFrames) }
	}

	if r.CheckResult.Features[host.FeatureKCSAN].Enabled && len(r.DataRaceFrames) != 0 {
		scheduler.filterDataRaceFrames(r.DataRaceFrames)
	}

	return gateCallback
}

func (scheduler *Scheduler) gateCallback(leakFrames []string) {
	// Leak checking is very slow so we don't do it while triaging the corpus
	// (otherwise it takes infinity). When we have presumably triaged the corpus
	// (triagedCandidates == 1), we run leak checking bug ignore the result
	// to flush any previous leaks. After that (triagedCandidates == 2)
	// we do actual leak checking and report leaks.
	triagedCandidates := atomic.LoadUint32(&scheduler.triagedCandidates)
	if triagedCandidates == 0 {
		return
	}
	args := append([]string{"leak"}, leakFrames...)
	timeout := scheduler.timeouts.NoOutput * 9 / 10
	output, err := osutil.RunCmd(timeout, "", scheduler.config.Executor, args...)
	if err != nil && triagedCandidates == 2 {
		// If we exit right away, dying executors will dump lots of garbage to console.
		os.Stdout.Write(output)
		fmt.Printf("BUG: leak checking failed\n")
		time.Sleep(time.Hour)
		os.Exit(1)
	}
	if triagedCandidates == 1 {
		atomic.StoreUint32(&scheduler.triagedCandidates, 2)
	}
}

func (scheduler *Scheduler) filterDataRaceFrames(frames []string) {
	args := append([]string{"setup_kcsan_filterlist"}, frames...)
	timeout := time.Minute * scheduler.timeouts.Scale
	output, err := osutil.RunCmd(timeout, "", scheduler.config.Executor, args...)
	if err != nil {
		log.Fatalf("failed to set KCSAN filterlist: %v", err)
	}
	log.Logf(0, "%s", output)
}

func (scheduler *Scheduler) updateEvDropRate() {
	progsTriggered := false
	for true {
		time.Sleep(time.Minute)

		scheduler.eventsMu.Lock()
		evts := scheduler.numEvents
		scheduler.numEvents = uint64(0)
		numBatches := len(scheduler.batches)
		curDropRate := scheduler.evDropRate
		scheduler.eventsMu.Unlock()
		newDropRate := 0

		if evts >= uint64(50000) {
			newDropRate = int(((evts - uint64(50000)) * 100) / evts)
		}
		if numBatches > 100 {
			if numBatches > 600 {
				if newDropRate < 75 {
					newDropRate = 75
				}
			} else {
				if progsTriggered {
					progsTriggered = false
				} else {
					newDropRate += 10
					progsTriggered = true
				}
			}
		}
		if newDropRate == 0 {
			if curDropRate > 10 {
				newDropRate = curDropRate - 10
			} else {
				newDropRate = 0
			}
		}
		if newDropRate >= 100 {
			newDropRate = 90
		}
		scheduler.eventsMu.Lock()
		scheduler.evDropRate = newDropRate
		scheduler.eventsMu.Unlock()
	}
}

func (scheduler *Scheduler) grabNewEvents() [][]prog.EvtrackEvent {
	scheduler.eventsMu.Lock()
	defer scheduler.eventsMu.Unlock()
	if len(scheduler.batches) == 0 {
		return nil
	}
	batch := scheduler.batches[0]
	if len(scheduler.batches) == 1 {
		scheduler.batches = make([]prog.Batch, 0)
	} else {
		scheduler.batches = scheduler.batches[1:]
	}
	return batch.Events
}

func (scheduler *Scheduler) grabNewSignal() signal.Signal {
	scheduler.signalMu.Lock()
	defer scheduler.signalMu.Unlock()
	sign := scheduler.newSignal
	if sign.Empty() {
		return nil
	}
	scheduler.newSignal = nil
	return sign
}

func readU32(data []byte) uint32 {
	return binary.LittleEndian.Uint32(data)
}

func readU64(data []byte) uint64 {
	return binary.LittleEndian.Uint64(data)
}

func writeU64(data []byte, num uint64) {
	binary.LittleEndian.PutUint64(data, num)
}

func (scheduler *Scheduler) addMaxSignal(sign signal.Signal) {
	if sign.Len() == 0 {
		return
	}
	scheduler.signalMu.Lock()
	defer scheduler.signalMu.Unlock()
	scheduler.maxSignal.Merge(sign)
}

func (scheduler *Scheduler) pollNew(needCandidates bool, stats map[string]uint64, shouldBuildEvChoiceTable bool) bool {
	a := &rpctype.PollArgsNew{
		Name:           scheduler.name,
		NeedCandidates: needCandidates,
		MaxSignal:      scheduler.grabNewSignal().Serialize(),
		Stats:          stats,
	}
	maxEvents := scheduler.grabNewEvents()
	r := &rpctype.SchedulerPollResNew{}
	// write data to ivshmem
	buf := evtrack.EncodeBatchPb(prog.Batch{Events: maxEvents})
	n := len(buf)
	m := copy(scheduler.ivshmem[8:], buf)
	if n != m {
		evts := 0
		for _, lst := range maxEvents {
			evts += len(lst)
		}
		log.Fatalf("buffer was too small for %v events(%v executions): %v(%v) instead of %v",
			evts, len(maxEvents), m, len(scheduler.ivshmem), n)
	}
	writeU64(scheduler.ivshmem[(8+n):], uint64(0))
	writeU64(scheduler.ivshmem, uint64(1)) // signal for host that shared mem is updated
	a.EvtLen = uint64(n)
	a.NewUsed = scheduler.evState.GetNewUsed()

	a.DeletedIDs = scheduler.deletedIDs

	if err := scheduler.manager.Call("Manager.SchedulerPollNew", a, r); err != nil {
		log.Fatalf("Manager.SchedulerPollNew call failed: %v", err)
	}
	// read data from ivshmem
	var changes []prog.Result
	if !scheduler.vanilla {
		if r.ChangeLen != 0 {
			dec := gob.NewDecoder(bytes.NewBuffer(scheduler.ivshmem[8:(8 + r.ChangeLen)]))
			err := dec.Decode(&changes)
			if err != nil {
				log.Fatalf("Decoding groups failed: %v", err)
			}
		}
		scheduler.deletedIDs = scheduler.evState.Update(changes, scheduler.target, scheduler.calls, shouldBuildEvChoiceTable)
	}

	maxSignal := r.MaxSignal.Deserialize()
	log.Logf(1, "poll: candidates=%v inputs=%v signal=%v groups=%v",
		len(r.Candidates), len(r.NewInputs), maxSignal.Len(), len(changes))
	scheduler.addMaxSignal(maxSignal)
	for _, inp := range r.NewInputs {
		scheduler.addInputFromAnotherFuzzer(inp)
	}
	for _, candidate := range r.Candidates {
		scheduler.addCandidateInput(candidate)
	}
	if needCandidates && len(r.Candidates) == 0 && atomic.LoadUint32(&scheduler.triagedCandidates) == 0 {
		atomic.StoreUint32(&scheduler.triagedCandidates, 1)
	}
	return len(r.NewInputs) != 0 || len(r.Candidates) != 0 || maxSignal.Len() != 0 ||
		len(changes) != 0
}

func (scheduler *Scheduler) addCandidateInput(candidate rpctype.UafCandidate) {
	p := scheduler.deserializeInput(candidate.Prog)
	if p == nil {
		return
	}
	flags := ProgCandidate
	if candidate.Minimized {
		flags |= ProgMinimized
	}
	if candidate.Smashed {
		flags |= ProgSmashed
	}
	scheduler.workQueue.enqueue(&WorkCandidate{
		p:       p,
		flags:   flags,
		UafInfo: candidate.UafInfo,
	})
}

func (scheduler *Scheduler) addInputFromAnotherFuzzer(inp rpctype.UafInput) {
	p := scheduler.deserializeInput(inp.Prog)
	if p == nil {
		return
	}
	uafCand := &uaf.UafCandiate{
		Prog:    p,
		UafInfo: inp.UafInfo,
	}
	sig := hash.Hash(inp.Prog, inp.UafInfo.Serialize())
	sign := inp.Signal.Deserialize()
	scheduler.addInputToCorpus(uafCand, sign, sig)
}

func (scheduler *Scheduler) addInputToCorpus(uafCand *uaf.UafCandiate, sign signal.Signal, sig hash.Sig) {
	scheduler.corpusMu.Lock()
	if _, ok := scheduler.corpusHashes[sig]; !ok {
		scheduler.corpus = append(scheduler.corpus, uafCand)
		scheduler.corpusHashes[sig] = struct{}{}
		prio := int64(len(sign))
		if sign.Empty() {
			prio = 1
		}
		scheduler.sumPrios += prio
		scheduler.corpusPrios = append(scheduler.corpusPrios, scheduler.sumPrios)
	}
	scheduler.corpusMu.Unlock()

	if !sign.Empty() {
		scheduler.signalMu.Lock()
		scheduler.corpusSignal.Merge(sign)
		scheduler.maxSignal.Merge(sign)
		scheduler.signalMu.Unlock()
	}
}

func (scheduler *Scheduler) deserializeInput(inp []byte) *prog.Prog {
	p, err := scheduler.target.Deserialize(inp, prog.NonStrict)
	if err != nil {
		log.Fatalf("failed to deserialize prog: %v\n%s", err, inp)
	}
	// We build choice table only after we received the initial corpus,
	// so we don't check the initial corpus here, we check it later in BuildChoiceTable.
	if scheduler.choiceTable != nil {
		scheduler.checkDisabledCalls(p)
	}
	if len(p.Calls) > prog.MaxCalls {
		return nil
	}
	return p
}

func (scheduler *Scheduler) checkDisabledCalls(p *prog.Prog) {
	for _, call := range p.Calls {
		if !scheduler.choiceTable.Enabled(call.Meta.ID) {
			fmt.Printf("executing disabled syscall %v [%v]\n", call.Meta.Name, call.Meta.ID)
			sandbox := ipc.FlagsToSandbox(scheduler.config.Flags)
			fmt.Printf("check result for sandbox=%v:\n", sandbox)
			for _, id := range scheduler.checkResult.EnabledCalls[sandbox] {
				meta := scheduler.target.Syscalls[id]
				fmt.Printf("  %v [%v]\n", meta.Name, meta.ID)
			}
			fmt.Printf("choice table:\n")
			for i, meta := range scheduler.target.Syscalls {
				fmt.Printf("  #%v: %v [%v]: enabled=%v\n", i, meta.Name, meta.ID, scheduler.choiceTable.Enabled(meta.ID))
			}
			panic("disabled syscall")
		}
	}
}

func (scheduler *Scheduler) getStrategies() {
	a := &rpctype.GetStratArg{
		Name: scheduler.name,
	}
	r := &rpctype.GetStratRes{}
	if err := scheduler.manager.Call("Manager.GetStrategies", a, r); err != nil {
		log.Fatalf("Manager.GetStrategies call failed: %v", err)
	}
	// read data from ivshmem
	var strats []prog.Strategy
	dec := gob.NewDecoder(bytes.NewBuffer(scheduler.ivshmem[8:(8 + r.Len)]))
	err := dec.Decode(&strats)
	if err != nil {
		log.Fatalf("Decoding groups failed: %v", err)
	}
	scheduler.evState.AddStrategies(strats)
}

func (scheduler *Scheduler) pollLoop() {
	var execTotal uint64
	var lastPoll time.Time
	var lastPrint time.Time
	ticker := time.NewTicker(3 * time.Second * scheduler.timeouts.Scale).C
	for {
		poll := false
		hasBatch := false
		select {
		case <-ticker:
		case <-scheduler.needPoll:
			poll = true
			select {
			case <-scheduler.hasBatch:
				hasBatch = true
			default:
			}
		case <-scheduler.hasBatch:
			hasBatch = true
		}
		if scheduler.outputType != OutputStdout && time.Since(lastPrint) > 10*time.Second*scheduler.timeouts.Scale {
			// Keep-alive for manager.
			log.Logf(0, "alive, executed %v", execTotal)
			lastPrint = time.Now()
		}
		if poll || hasBatch || time.Since(lastPoll) > 10*time.Second*scheduler.timeouts.Scale {
			needCandidates := scheduler.workQueue.wantCandidates()
			if poll && !needCandidates && !hasBatch {
				continue
			}
			stats := make(map[string]uint64)
			for _, proc := range scheduler.procs {
				stats["exec total"] += atomic.SwapUint64(&proc.env.StatExecs, 0)
				stats["executor restarts"] += atomic.SwapUint64(&proc.env.StatRestarts, 0)
			}
			for stat := Stat(0); stat < StatCount; stat++ {
				v := atomic.SwapUint64(&scheduler.stats[stat], 0)
				stats[statNames[stat]] = v
				execTotal += v
			}
			if !scheduler.pollNew(needCandidates, stats, true) {
				lastPoll = time.Now()
			}
		}
	}
}

func (scheduler *Scheduler) snapshot() FuzzerSnapshot {
	scheduler.corpusMu.RLock()
	defer scheduler.corpusMu.RUnlock()
	return FuzzerSnapshot{scheduler.corpus, scheduler.corpusPrios, scheduler.sumPrios}
}

func (fuzzer *FuzzerSnapshot) chooseProgram(r *rand.Rand) *uaf.UafCandiate {
	randVal := r.Int63n(fuzzer.sumPrios + 1)
	idx := sort.Search(len(fuzzer.corpusPrios), func(i int) bool {
		return fuzzer.corpusPrios[i] >= randVal
	})
	return fuzzer.corpus[idx]
}

func (scheduler *Scheduler) checkNewSignal(p *prog.Prog, info *ipc.ProgInfo) (calls []int, extra bool) {
	scheduler.signalMu.RLock()
	defer scheduler.signalMu.RUnlock()
	for i, inf := range info.Calls {
		if scheduler.checkNewCallSignal(p, &inf, i) {
			calls = append(calls, i)
		}
	}
	extra = scheduler.checkNewCallSignal(p, &info.Extra, -1)
	return
}

func (scheduler *Scheduler) checkNewCallSignal(p *prog.Prog, info *ipc.CallInfo, call int) bool {
	diff := scheduler.maxSignal.DiffRaw(info.Signal, signalPrio(p, info, call))
	if diff.Empty() {
		return false
	}
	scheduler.signalMu.RUnlock()
	scheduler.signalMu.Lock()
	scheduler.maxSignal.Merge(diff)
	scheduler.newSignal.Merge(diff)
	scheduler.signalMu.Unlock()
	scheduler.signalMu.RLock()
	return true
}

func signalPrio(p *prog.Prog, info *ipc.CallInfo, call int) (prio uint8) {
	if call == -1 {
		return 0
	}
	if info.Errno == 0 {
		prio |= 1 << 1
	}
	if !p.Target.CallContainsAny(p.Calls[call]) {
		prio |= 1 << 0
	}
	return
}

func (scheduler *Scheduler) checkNewEvents(p *prog.Prog, info *ipc.ProgInfo) {
	// we could also accept the race here versus the update to reduce locking effort
	scheduler.eventsMu.Lock()
	if rand.Intn(100) < scheduler.evDropRate {
		scheduler.eventsMu.Unlock()
		return
	}
	scheduler.eventsMu.Unlock()

	var curBatch *prog.Batch = scheduler.getCurBatch()

	var flattened []prog.EvtrackEvent
	for i, call := range info.Calls {
		// To completely ignore events from the 14 banned syscalls, check for the name and continue here
		name := p.Calls[i].Meta.Name
		if _, ok := scheduler.banned[name]; ok {
			continue
		}
		for j := range call.EvList {
			call.EvList[j].Syscall = p.Calls[i].Meta.Name
			call.EvList[j].Args = make([]prog.Arg, len(p.Calls[i].Args))
			copy(call.EvList[j].Args, p.Calls[i].Args)
		}
		flattened = append(flattened, call.EvList...)
	}
	curBatch.Events = append(curBatch.Events, flattened)
	curBatch.Size += uint64(len(flattened))

	scheduler.eventsMu.Lock()
	defer scheduler.eventsMu.Unlock()
	scheduler.numEvents += uint64(len(flattened))
	scheduler.batches[len(scheduler.batches)-1] = *curBatch
	if curBatch.Size >= 2000 {
		curBatch = new(prog.Batch)
		curBatch.Size = 0
		curBatch.Events = make([][]prog.EvtrackEvent, 0)
		scheduler.batches = append(scheduler.batches, *curBatch)
		select {
		case scheduler.hasBatch <- true:
		default:
			// the queue is already full, we don't need to add more to it
		}
	}
}

func (scheduler *Scheduler) getCurBatch() *prog.Batch {
	scheduler.eventsMu.Lock()
	defer scheduler.eventsMu.Unlock()
	var curBatch prog.Batch
	if len(scheduler.batches) > 0 {
		ind := len(scheduler.batches) - 1
		curBatch.Events = append(curBatch.Events, scheduler.batches[ind].Events...)
		curBatch.Size = scheduler.batches[ind].Size
	} else {
		scheduler.batches = append(scheduler.batches, curBatch)
	}
	return &curBatch
}

func (scheduler *Scheduler) corpusSignalDiff(sign signal.Signal) signal.Signal {
	scheduler.signalMu.RLock()
	defer scheduler.signalMu.RUnlock()
	return scheduler.corpusSignal.Diff(sign)
}

func (scheduler *Scheduler) sendInputToManager(inp rpctype.UafInput) {
	a := &rpctype.NewUafInputArgs{
		Name:     scheduler.name,
		UafInput: inp,
	}
	if err := scheduler.manager.Call("Manager.NewUafInput", a, nil); err != nil {
		log.Fatalf("Manager.NewUafInput call failed: %v", err)
	}
}
