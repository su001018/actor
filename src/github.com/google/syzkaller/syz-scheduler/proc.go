package main

import (
	"math/rand"

	"github.com/google/syzkaller/pkg/ipc"
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
