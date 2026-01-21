package main

import (
	"log"
	_ "net/http/pprof" // 导入pprof包，自动注册路由
	"os"
	"os/signal"
	"syscall"
	"webRTCInfra/pkg/entry"
)

func main() {
	httpAddr := ":8080" // HTTP服务地址
	stunAddr := ":3478" // STUN服务地址
	publicIP := "192.168.1.1"

	// 启动HTTP服务，暴露pprof接口（默认端口6060）
	// go func() {
	// 	_ = http.ListenAndServe(":7070", nil)
	// }()

	server := entry.NewServer(httpAddr, stunAddr, publicIP)
	if err := server.Start(); err != nil {
		log.Fatalf("failed to start server：%v", err)
	}

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	<-sigChan

	log.Println("shutting down server...")
	server.Close()
	log.Println("server closed")
}
