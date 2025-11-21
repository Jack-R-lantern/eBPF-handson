package topology

import (
	"fmt"
	"net"
	"runtime"

	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
)

const (
	// Namespace
	NamespaceRoot = "root"
	NamespaceA    = "ns-a"
	NamespaceB    = "ns-b"

	// veth host
	VethAHostName = "veth-a-host"
	VethAPeerName = "veth-a-peer"
	VethBHostName = "veth-b-host"
	VethBPeerName = "veth-b-peer"

	VethAIPv4CIDR = "10.0.1.1/24"
	VethBIPv4CIDR = "10.0.1.2/24"
)

type Program struct {
	Name      string
	Direction string
}

type Endpoint struct {
	IfIndex   int
	Name      string
	IP        net.IP
	Namespace string
	IsRoot    bool
	Peer      string
	Programs  []Program
}

type Topology struct {
	Endpoints map[string]*Endpoint
}

func (tp *Topology) ConvertDTO() TopologyDTO {
	endpoints := make([]EndpointDTO, 0, len(tp.Endpoints))

	for name, ep := range tp.Endpoints {
		// Programs 변환
		programs := make([]ProgramDTO, 0, len(ep.Programs))
		for _, p := range ep.Programs {
			programs = append(programs, ProgramDTO{
				Name:      p.Name,
				Direction: p.Direction, // "ingress" / "egress"로 맞춰두면 그대로
			})
		}

		endpoints = append(endpoints, EndpointDTO{
			Name:      name, // map key를 name으로 노출하거나
			IfIndex:   ep.IfIndex,
			IP:        ep.IP.String(), // net.IP -> string
			Namespace: ep.Namespace,
			IsRoot:    ep.IsRoot,
			Peer:      ep.Peer,
			Programs:  programs,
		})
	}

	return TopologyDTO{
		Endpoints: endpoints,
	}
}

type linkConfig struct {
	hostName  string
	peerName  string
	namespace string
	ipcidr    string
}

// Setup
func Setup() (*Topology, error) {
	cfgs := []linkConfig{
		{
			hostName:  VethAHostName,
			peerName:  VethAPeerName,
			namespace: NamespaceA,
			ipcidr:    VethAIPv4CIDR,
		},
		{
			hostName:  VethBHostName,
			peerName:  VethBPeerName,
			namespace: NamespaceB,
			ipcidr:    VethBIPv4CIDR,
		},
	}
	for _, cfg := range cfgs {
		if err := createNS(cfg.namespace); err != nil {
			return nil, err
		}
	}

	for _, cfg := range cfgs {
		if err := createVethPair(cfg.hostName, cfg.peerName, cfg.namespace); err != nil {
			return nil, err
		}
	}

	if err := setupNSInterface(cfgs); err != nil {
		return nil, err
	}

	topology, err := collectTopology(&cfgs)
	if err != nil {
		return nil, fmt.Errorf("collect topology: %w", err)
	}

	return topology, nil
}

// CleanuP
func Cleanup() {
	_ = WithNetNameSpace(NamespaceRoot, func() error {
		for _, name := range []string{VethAHostName, VethBHostName} {
			if link, err := netlink.LinkByName(name); err == nil {
				_ = netlink.LinkDel(link)
			}
		}
		return nil
	})

	netns.DeleteNamed(NamespaceA)
	netns.DeleteNamed(NamespaceB)
}

func createNS(name string) error {
	return WithNetNameSpace(NamespaceRoot, func() error {
		ns, err := netns.NewNamed(name)
		if err != nil {
			return fmt.Errorf("create %s netns: %w", name, err)
		}
		ns.Close()
		return nil
	})
}

// WithNetNameSpace
func WithNetNameSpace(named string, fn func() error) error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	curNamespace, err := netns.Get()
	if err != nil {
		return fmt.Errorf("get current netns: %w", err)
	}
	defer curNamespace.Close()
	defer netns.Set(curNamespace)

	var target netns.NsHandle
	if named == NamespaceRoot {
		target = curNamespace
	} else {
		target, err = netns.GetFromName(named)
		if err != nil {
			return fmt.Errorf("get netns %s: %w", named, err)
		}
		defer target.Close()
		if err := netns.Set(target); err != nil {
			return fmt.Errorf("set netns %s: %w", named, err)
		}
	}

	return fn()
}

func createVethPair(hostName, peerName, namespaceName string) error {
	return WithNetNameSpace(NamespaceRoot, func() error {
		attrs := netlink.NewLinkAttrs()
		attrs.Name = hostName
		veth := &netlink.Veth{
			LinkAttrs: attrs,
			PeerName:  peerName,
		}
		// veth create
		if err := netlink.LinkAdd(veth); err != nil {
			return fmt.Errorf("add %s: %w", hostName, err)
		}

		// peer look up
		peer, err := netlink.LinkByName(peerName)
		if err != nil {
			return fmt.Errorf("get %s: %w", peerName, err)
		}

		// namespace lookup
		namespace, err := netns.GetFromName(namespaceName)
		if err != nil {
			return fmt.Errorf("get %s handle: %w", namespaceName, err)
		}
		defer namespace.Close()

		if err := netlink.LinkSetNsFd(peer, int(namespace)); err != nil {
			return fmt.Errorf("move %s to %s: %w", peerName, namespaceName, err)
		}
		return nil
	})
}

func setupNSInterface(cfgs []linkConfig) error {
	// 1) root
	if err := WithNetNameSpace(NamespaceRoot, func() error {
		for _, name := range []string{VethAHostName, VethBHostName} {
			link, err := netlink.LinkByName(name)
			if err != nil {
				return fmt.Errorf("root: get %s: %w", name, err)
			}
			if err := netlink.LinkSetUp(link); err != nil {
				return fmt.Errorf("root: set %s: %w", name, err)
			}
		}
		return nil
	}); err != nil {
		return err
	}

	for _, cfg := range cfgs {
		if err := WithNetNameSpace(cfg.namespace, func() error {
			if lo, err := netlink.LinkByName("lo"); err != nil {
				_ = netlink.LinkSetUp(lo)
			}

			link, err := netlink.LinkByName(cfg.peerName)
			if err != nil {
				return fmt.Errorf("%s: get %s: %w", cfg.namespace, cfg.peerName, err)
			}

			addr, err := netlink.ParseAddr(cfg.ipcidr)
			if err != nil {
				return fmt.Errorf("%s: parse addr: %w", cfg.namespace, err)
			}

			if err := netlink.AddrAdd(link, addr); err != nil {
				return fmt.Errorf("%s: addr add: %w", cfg.namespace, err)
			}

			if err := netlink.LinkSetUp(link); err != nil {
				return fmt.Errorf("%s: set %s up: %w", cfg.namespace, cfg.peerName, err)
			}

			return nil
		}); err != nil {
			return err
		}
	}
	return nil
}

func collectTopology(cfgs *[]linkConfig) (*Topology, error) {
	topology := &Topology{
		Endpoints: make(map[string]*Endpoint),
	}

	// veth host
	for _, cfg := range *cfgs {
		if err := WithNetNameSpace(NamespaceRoot, func() error {
			link, err := netlink.LinkByName(cfg.hostName)
			if err != nil {
				return fmt.Errorf("%s: get %s: %w", NamespaceRoot, cfg.hostName, err)
			}
			topology.Endpoints[cfg.hostName] = &Endpoint{
				IfIndex:   link.Attrs().Index,
				Name:      cfg.hostName,
				IP:        nil,
				Namespace: NamespaceRoot,
				IsRoot:    true,
				Peer:      cfg.peerName,
				Programs:  make([]Program, 0),
			}
			return nil
		}); err != nil {
			return nil, err
		}
	}

	// veth peer
	for _, cfg := range *cfgs {
		if err := WithNetNameSpace(cfg.namespace, func() error {
			link, err := netlink.LinkByName(cfg.peerName)
			if err != nil {
				return fmt.Errorf("%s: get %s: %w", cfg.namespace, cfg.peerName, err)
			}

			addrs, err := netlink.AddrList(link, netlink.FAMILY_V4)
			if err != nil {
				return fmt.Errorf("%s: list addrs: %w", cfg.namespace, err)
			}

			var ip net.IP
			if len(addrs) > 0 {
				ip = addrs[0].IP
			}

			topology.Endpoints[cfg.peerName] = &Endpoint{
				IfIndex:   link.Attrs().Index,
				Name:      cfg.peerName,
				IP:        ip,
				Namespace: cfg.namespace,
				IsRoot:    false,
				Peer:      cfg.hostName,
				Programs:  make([]Program, 0),
			}
			return nil
		}); err != nil {
			return nil, err
		}
	}

	return topology, nil
}
