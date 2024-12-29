package debug

import (
	"fmt"
	"log"
	"os"
)

func LogDebug(format string, a ...interface{}) {
	//debug
	debugFile, err := os.OpenFile("/home/dengnan/workdir/schduleFuzz/actor/src/github.com/google/syzkaller/pkg/debug/debug.txt", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Fatalf("Error opening file: %+v", err)
	}
	defer debugFile.Close()

	fmt.Fprintf(debugFile, format, a...)
}
