package api

import "github.com/gin-gonic/gin"

func SetRouter(routerGroup *gin.RouterGroup, ctr *Controller) {
	routerGroup.POST("test", ctr.TestSetup)
	routerGroup.GET("topology", ctr.GetTopology)
}
