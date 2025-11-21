package topology

type ProgramDTO struct {
	Name      string `json:"name"`
	Direction string `json:"direction"` // ingress/egress
}

type EndpointDTO struct {
	Name      string       `json:"name"`
	IfIndex   int          `json:"ifIndex"`
	IP        string       `json:"ip"`
	Namespace string       `json:"namespace"`
	IsRoot    bool         `json:"isRoot"`
	Peer      string       `json:"peer"`
	Programs  []ProgramDTO `json:"programs"`
}

type TopologyDTO struct {
	Endpoints []EndpointDTO `json:"endpoints"`
}
