package api

import (
	"net/http"

	"github.com/cilium/ebpf"
	"github.com/gin-gonic/gin"

	"github.com/Jack-R-lantern/eBPF-handson/ddos-block/internal/netutil"
)

func ListHandler(blockMap *ebpf.Map) gin.HandlerFunc {
	return func(c *gin.Context) {
		iter := blockMap.Iterate()
		var k uint32
		var v uint8
		out := make([]string, 0, 128)

		for iter.Next(&k, &v) {
			out = append(out, netutil.U32ToIPv4(k))
		}
		if err := iter.Err(); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusOK, gin.H{"blocked": out})
	}
}
