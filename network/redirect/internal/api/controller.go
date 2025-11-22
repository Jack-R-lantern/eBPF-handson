package api

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/Jack-R-lantern/eBPF-handson/redirect/internal/bpf"
	"github.com/Jack-R-lantern/eBPF-handson/redirect/internal/scenario"
	"github.com/Jack-R-lantern/eBPF-handson/redirect/internal/topology"
)

type Controller struct {
	bpfManager *bpf.BPFManager
	tp         *topology.Topology
	runner     *scenario.Runner
}

func NewController(mgr *bpf.BPFManager, tp *topology.Topology) *Controller {
	return &Controller{
		bpfManager: mgr,
		tp:         tp,
		runner:     scenario.NewRunner(mgr, tp),
	}
}

type scenarioRequest struct {
	Scenario string `json:"scenario"`
}

type testResponse struct {
	Scenario string               `json:"scenario"`
	From     scenario.EndpointRef `json:"from"`
	To       scenario.EndpointRef `json:"to"`
	Path     []scenario.PathStep  `json:"path"`
	Status   string               `json:"status"`
}

func (ctr *Controller) TestSetup(ctx *gin.Context) {
	var req scenarioRequest
	if err := ctx.ShouldBindJSON(&req); err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{
			"error": "invalid request body",
		})
		return
	}

	result, err := ctr.runScenario(ctx, req.Scenario)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{
			"status":  "error",
			"message": err.Error(),
		})
		return
	}

	ctx.JSON(http.StatusOK, result)
}

func (ctr *Controller) GetTopology(ctx *gin.Context) {
	dto := ctr.tp.ConvertDTO()
	ctx.JSON(http.StatusOK, dto)
}

func (ctr *Controller) runScenario(ctx *gin.Context, scenario string) (testResponse, error) {
	result, err := ctr.runner.Run(ctx.Request.Context(), scenario)
	if err != nil {
		return testResponse{}, err
	}

	return testResponse(result), nil
}
