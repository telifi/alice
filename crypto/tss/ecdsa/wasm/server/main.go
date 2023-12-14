package main

import (
	"fmt"
)

func loginfo(format string, args ...any) {
	s := fmt.Sprintf(format, args...)
	fmt.Println(s)
}

func main() {
	sm := NewServiceManager()

	wsServer := NewWebSocketServer(":8080")
	wsServer.AddListener(sm.NewClient)
	go wsServer.Start()
	go sm.WatchRegister()

	fmt.Println("listen 8080")
	select {}
}
