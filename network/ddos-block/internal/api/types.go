package api

type BlockReq struct {
	IP string `json:"ip" binding:"required"`
}
