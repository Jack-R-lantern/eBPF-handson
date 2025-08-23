package api

import (
	"errors"
	"fmt"
	"net/http"

	"github.com/cilium/ebpf"
	"github.com/gin-gonic/gin"

	"github.com/Jack-R-lantern/eBPF-handson/ddos-block/internal/netutil"
)

func ClearHandler(blockMap *ebpf.Map) gin.HandlerFunc {
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
		if err := blockMap.Delete(key); err != nil {
			if errors.Is(err, ebpf.ErrKeyNotExist) {
				c.JSON(http.StatusNotFound, gin.H{"status": "not_found", "ip": req.IP})
				return
			}
			c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("map delete: %v", err)})
			return
		}
		c.JSON(http.StatusOK, gin.H{"status": "ok", "cleared": req.IP})
	}
}
