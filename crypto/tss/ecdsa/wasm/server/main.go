package main

import (
	"fmt"
	"runtime"
)

func loginfo(format string, args ...any) {
	s := fmt.Sprintf(format, args...)
	fmt.Println(s)
}

func main() {
	sm := NewServiceManager()
	loginfo("Num CPU:%v", runtime.NumCPU())
	loginfo("Set total go routine %v", runtime.GOMAXPROCS(24))
	wsServer := NewWebSocketServer(":8080")
	wsServer.AddListener(sm.NewClient)
	go wsServer.Start()
	go sm.WatchRegister()

	fmt.Println("listen 8080")
	select {}
}
