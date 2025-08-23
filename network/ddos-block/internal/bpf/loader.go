package bpf

import (
	"fmt"
	"net"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

type Loader struct {
	Coll     *ebpf.Collection
	Links    []link.Link
	BlockMap *ebpf.Map
}

// LoadAndAttach: ELF 로드 → 맵 핸들 획득 → XDP 부착
func LoadAndAttach(objPath, ifName, mapName string) (*Loader, error) {
	iface, err := net.InterfaceByName(ifName)
	if err != nil {
		return nil, fmt.Errorf("interface: %w", err)
	}

	coll, err := ebpf.LoadCollection(objPath)
	if err != nil {
		return nil, fmt.Errorf("load collection: %w", err)
	}

	bm, ok := coll.Maps[mapName]
	if !ok {
		coll.Close()
		return nil, fmt.Errorf("map %q not found", mapName)
	}

	var links []link.Link
	for name, prog := range coll.Programs {
		lk, err := link.AttachXDP(link.XDPOptions{
			Program:   prog,
			Interface: iface.Index,
			Flags:     link.XDPGenericMode,
		})
		if err != nil {
			// 실패 시 이미 붙인 링크 해제하고 종료
			for _, l := range links {
				_ = l.Close()
			}
			coll.Close()
			return nil, fmt.Errorf("attach xdp (%s): %w", name, err)
		}
		links = append(links, lk)
	}

	return &Loader{
		Coll:     coll,
		Links:    links,
		BlockMap: bm,
	}, nil
}

func (l *Loader) Close() {
	for _, lk := range l.Links {
		_ = lk.Close()
	}
	if l.Coll != nil {
		l.Coll.Close()
	}
}
