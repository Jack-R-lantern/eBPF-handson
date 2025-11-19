package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/Jack-R-lantern/eBPF-handson/redirect/internal/bpf"
	"github.com/Jack-R-lantern/eBPF-handson/redirect/internal/logger"
	"github.com/Jack-R-lantern/eBPF-handson/redirect/internal/topology"
)

const (
	httpAddrEnv    = "TEST_ADDRESS"
	bpfObjectEnv   = "BPF_OBJECT_PATH"
	managerContext = "bpf_manager"
	topologyCtx    = "topology"
)

type config struct {
	HTTPAddr      string
	BPFObjectPath string
}

func main() {
	baseLogger, err := logger.New(logger.OptionsFromEnv())
	if err != nil {
		fmt.Fprintf(os.Stderr, "init logger: %v\n", err)
		os.Exit(1)
	}
	serviceLogger := baseLogger.With("service", "redirect")

	cfg, err := loadConfig()
	if err != nil {
		serviceLogger.Error("load config", "err", err)
		os.Exit(1)
	}

	tp, err := topology.Setup()
	if err != nil {
		serviceLogger.Error("setup topology", "err", err)
		os.Exit(1)
	}
	defer func() {
		serviceLogger.Info("cleaning up toplogy")
		topology.Cleanup()
	}()

	mgrLogger := serviceLogger.With("component", "bpf_manager")
	mgr, err := bpf.NewBPFManger(cfg.BPFObjectPath, mgrLogger)
	if err != nil {
		serviceLogger.Error("init bpf manager", "err", err)
		os.Exit(1)
	}
	defer func() {
		if err := mgr.Cleanup(); err != nil {
			mgrLogger.Error("cleanup bpf manager", "err", err)
		}
	}()

	if err := mgr.Setup(tp); err != nil {
		mgrLogger.Error("attach trace programs", "err", err)
		os.Exit(1)
	}

	router := gin.New()
	router.Use(gin.Recovery())
	router.Use(func(ctx *gin.Context) {
		requestID := fmt.Sprintf("%d", time.Now().UnixNano())
		reqLogger := serviceLogger.With(
			"component", "http",
			"request_id", requestID,
			"method", ctx.Request.Method,
			"path", ctx.Request.URL.Path,
		)
		cctx := logger.ContextWithLogger(ctx.Request.Context(), reqLogger)
		ctx.Request = ctx.Request.WithContext(cctx)

		ctx.Set(managerContext, mgr)
		ctx.Set(topologyCtx, tp)

		start := time.Now()
		ctx.Next()
		reqLogger.Info("request completed", "status", ctx.Writer.Status(), "duration", time.Since(start))
	})

	srv := &http.Server{
		Addr:    cfg.HTTPAddr,
		Handler: router,
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	srvLogger := serviceLogger.With("component", "http_server", "addr", cfg.HTTPAddr)
	go func() {
		srvLogger.Info("HTTP server listening")
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			srvLogger.Error("ListenAndServe", "err", err)
			stop()
		}
	}()

	<-ctx.Done()
	srvLogger.Info("shutdown signal received")

	ctxShutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := srv.Shutdown(ctxShutdown); err != nil {
		srvLogger.Error("HTTP shutdown", "err", err)
	}

	<-ctxShutdown.Done()
}

func loadConfig() (config, error) {
	cfg := config{
		HTTPAddr:      os.Getenv(httpAddrEnv),
		BPFObjectPath: os.Getenv(bpfObjectEnv),
	}
	if cfg.HTTPAddr == "" {
		return config{}, fmt.Errorf("%s must be set", httpAddrEnv)
	}
	if cfg.BPFObjectPath == "" {
		return config{}, fmt.Errorf("%s must be set", bpfObjectEnv)
	}
	return cfg, nil
}
