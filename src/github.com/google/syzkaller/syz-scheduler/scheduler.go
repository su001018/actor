package main

import (
	"sync"

	"github.com/google/syzkaller/pkg/hash"
	"github.com/google/syzkaller/pkg/host"
	"github.com/google/syzkaller/pkg/ipc"
	"github.com/google/syzkaller/pkg/rpctype"
	"github.com/google/syzkaller/pkg/signal"
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
	corpus       []*uaf.UafProg
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
