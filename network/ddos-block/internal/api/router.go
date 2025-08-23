package api

import (
	"github.com/cilium/ebpf"
	"github.com/gin-gonic/gin"
)

func SetupRoutes(r *gin.Engine, blockMap *ebpf.Map) {
	// 핸들러에 맵 핸들 주입
	r.POST("/block", BlockHandler(blockMap))
	r.POST("/clear", ClearHandler(blockMap))
	r.GET("/list", ListHandler(blockMap))
}
