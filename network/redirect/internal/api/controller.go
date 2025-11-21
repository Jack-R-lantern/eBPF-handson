package api

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/Jack-R-lantern/eBPF-handson/redirect/internal/bpf"
	"github.com/Jack-R-lantern/eBPF-handson/redirect/internal/topology"
)

type Controller struct {
	bpfManager *bpf.BPFManager
	tp         *topology.Topology
}

func NewController(mgr *bpf.BPFManager, tp *topology.Topology) *Controller {
	return &Controller{
		bpfManager: mgr,
		tp:         tp,
	}
}

type scenarioRequest struct {
	Scenario string `json:"scenario"`
}

func (ctr *Controller) TestSetup(ctx *gin.Context) {
	var req scenarioRequest
	if err := ctx.ShouldBindJSON(&req); err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{
			"error": "invalid request body",
		})
		return
	}

	if err := ctr.bpfManager.TestSetup(req.Scenario, ctr.tp); err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{
			"status":  "error",
			"message": err.Error(),
		})
		return
	}

	ctx.JSON(http.StatusOK, gin.H{
		"status":   "ok",
		"scenario": req.Scenario,
	})
}

func (ctr *Controller) GetTopology(ctx *gin.Context) {
	dto := ctr.tp.ConvertDTO()
	ctx.JSON(http.StatusOK, dto)
}
