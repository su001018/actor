package main

import (
	"github.com/google/syzkaller/prog"
	"testing"
)

func TestSaveUAFProg(t *testing.T) {
	callPairMap := make(map[int]map[int]int)
	callPairMap[0] = make(map[int]int)
	callPairMap[1] = make(map[int]int)
	callPairMap[0][1] = 1
	callPairMap[0][2] = 1
	callPairMap[1][3] = 1
	callPairMap[1][4] = 1

	p := &prog.Prog{
		Target:   &prog.Target{},
		Calls:    make([]*prog.Call, 5),
		Comments: make([]string, 0),
	}

	SaveUAFProg(p, callPairMap)
}
