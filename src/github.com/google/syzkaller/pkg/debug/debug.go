package debug

import (
	"fmt"
	"log"
	"os"
	"time"
)

func LogDebug(format string, a ...interface{}) {
	// 获取当前时间并格式化
	now := time.Now()
	timeFormat := "2006/01/02 15:04:05"
	formattedTime := now.Format(timeFormat)

	// 打开文件
	debugFile, err := os.OpenFile("/home/dengnan/workdir/schduleFuzz/actor/src/github.com/google/syzkaller/pkg/debug/debug.txt", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Fatalf("Error opening file: %+v", err)
	}
	defer debugFile.Close()

	// 在日志信息前添加时间
	logMessage := fmt.Sprintf("[%s] %s", formattedTime, fmt.Sprintf(format, a...))

	// 将包含时间的日志信息写入文件
	fmt.Fprintln(debugFile, logMessage)
}
