package main

import (
	"context"
	"flag"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/Jack-R-lantern/eBPF-handson/ddos-block/internal/api"
	"github.com/Jack-R-lantern/eBPF-handson/ddos-block/internal/bpf"
	"github.com/gin-gonic/gin"
)

func main() {
	var (
		objPath = flag.String("obj", "", "path to BPF ELF object (required)")
		ifName  = flag.String("if", "eth0", "interface name for XDP attach")
		addr    = flag.String("addr", "127.0.0.1:8080", "HTTP listen addr")
		mapName = flag.String("map", "blocked_ips", "BPF map name (IPv4 key)")
	)
	flag.Parse()
	if *objPath == "" {
		log.Fatalf("use -obj /path/to/xdp.o")
	}

	// 2) BPF 로드 & XDP 부착
	loader, err := bpf.LoadAndAttach(*objPath, *ifName, *mapName)
	if err != nil {
		log.Fatalf("bpf load/attach: %v", err)
	}
	defer loader.Close()

	// 3) Gin 라우터 구성 (맵 핸들 주입)
	r := gin.Default()
	api.SetupRoutes(r, loader.BlockMap)

	// 4) HTTP 서버 + 그레이스풀 종료
	srv := &http.Server{Addr: *addr, Handler: r}
	go func() {
		log.Printf("HTTP listening on http://%s", *addr)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("ListenAndServe: %v", err)
		}
	}()

	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	<-sigs

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_ = srv.Shutdown(ctx)
}
