package api

import (
	"fmt"
	"net/http"

	"github.com/cilium/ebpf"
	"github.com/gin-gonic/gin"

	"github.com/Jack-R-lantern/eBPF-handson/ddos-block/internal/netutil"
)

func BlockHandler(blockMap *ebpf.Map) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req BlockReq
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid JSON, want {\"ip\":\"A.B.C.D\"}"})
			return
		}
		key, err := netutil.IPv4ToU32(req.IP)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("invalid IPv4: %v", err)})
			return
		}
		val := uint8(1)
		if err := blockMap.Update(key, val, ebpf.UpdateAny); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("map update: %v", err)})
			return
		}
		c.JSON(http.StatusOK, gin.H{"status": "ok", "blocked": req.IP})
	}
}
