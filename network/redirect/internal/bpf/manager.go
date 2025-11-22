package bpf

import (
	"errors"
	"fmt"
	"log/slog"

	"github.com/cilium/ebpf"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	"github.com/Jack-R-lantern/eBPF-handson/redirect/internal/topology"
)

const (
	REDIRECT_TEST_PROG_NAME = "redirect"

	ENDPOINTS_MAP_NAME    = "endpoints"
	REDIRECT_DIR_MAP_NAME = "redirect_dir"
	TEST_SELECT_MAP_NAME  = "test_select"

	TEST_SELECT_REDIRECT      uint32 = 0
	TEST_SELECT_REDIRECT_PEER uint32 = 1

	TRACE_PEER_INGRESS_PROG_NAME = "tr_peer_in"
	TRACE_PEER_EGRESS_PROG_NAME  = "tr_peer_out"
	TRACE_HOST_INGRESS_PROG_NAME = "tr_host_in"
	TRACE_HOST_EGRESS_PROG_NAME  = "tr_host_out"

	TRACE_MAP = "trace"

	QDISC_ID = 0xffff

	// bpf key direction
	A_PEER_NAMESPACE_EGRESS  uint32 = 1 << 0
	A_HOST_NAMESPACE_INGRESS uint32 = 1 << 1
	B_HOST_NAMESPACE_EGRESS  uint32 = 1 << 2
	B_PEER_NAMESPACE_INGRESS uint32 = 1 << 3
)

type TraceInfo struct {
	TraversedPath uint32
	Pad           uint32
	LastSeen      uint64
}

type TraceEntry struct {
	Key   uint32
	Value TraceInfo
}

type tcQdiscRef struct {
	IfName    string
	Namespace string
}

type tcFilterRef struct {
	IfName    string
	Namespace string
	Parent    uint32
	Name      string
}

type endpointInfo struct {
	IfIndex uint32
	Pad     uint32
}

type BPFManager struct {
	spec       *ebpf.CollectionSpec
	collection *ebpf.Collection

	qdiscs  map[string]tcQdiscRef
	filters map[string]tcFilterRef

	logger *slog.Logger
}

func NewBPFManger(path string, log *slog.Logger) (*BPFManager, error) {
	if log == nil {
		return nil, fmt.Errorf("logger must not be nil")
	}

	mgr := &BPFManager{
		qdiscs:  make(map[string]tcQdiscRef),
		filters: make(map[string]tcFilterRef),
		logger:  log,
	}

	mgr.logger.With("object", path).Info("loading BPF Collection")
	if err := mgr.loadObjectSpec(path); err != nil {
		return nil, err
	}

	return mgr, nil
}

func (mgr *BPFManager) loadObjectSpec(path string) error {
	spec, err := ebpf.LoadCollectionSpec(path)
	if err != nil {
		return fmt.Errorf("load collection failed: %w", err)
	}
	mgr.spec = spec

	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		return fmt.Errorf("load collection failed: %w", err)
	}
	mgr.collection = coll

	return nil
}

func (mgr *BPFManager) Setup(tp *topology.Topology) error {
	// VethA Peer Setting
	vethAPeer := tp.Endpoints[topology.VethAPeerName]
	if err := mgr.setQdisc(vethAPeer.Name, vethAPeer.Namespace); err != nil {
		return err
	}
	if err := mgr.setFilter(
		vethAPeer,
		netlink.HANDLE_MIN_EGRESS,
		mgr.collection.Programs[TRACE_PEER_EGRESS_PROG_NAME],
	); err != nil {
		return err
	}

	// VethA Host Setting
	vethAHost := tp.Endpoints[topology.VethAHostName]
	if err := mgr.collection.Maps[TEST_SELECT_MAP_NAME].Put(uint32(0), TEST_SELECT_REDIRECT); err != nil {
		return err
	}
	if err := mgr.setQdisc(vethAHost.Name, vethAHost.Namespace); err != nil {
		return err
	}
	if err := mgr.setFilter(
		vethAHost,
		netlink.HANDLE_MIN_INGRESS,
		mgr.collection.Programs[REDIRECT_TEST_PROG_NAME],
	); err != nil {
		return err
	}
	if err := mgr.collection.Maps[ENDPOINTS_MAP_NAME].Put(uint32(1), endpointInfo{IfIndex: uint32(vethAHost.IfIndex)}); err != nil {
		return err
	}

	// VethB Host Setting
	vethBHost := tp.Endpoints[topology.VethBHostName]

	if err := mgr.collection.Maps[ENDPOINTS_MAP_NAME].Put(uint32(0), endpointInfo{IfIndex: uint32(vethBHost.IfIndex)}); err != nil {
		return err
	}

	if err := mgr.setQdisc(vethBHost.Name, vethBHost.Namespace); err != nil {
		return err
	}
	if err := mgr.setFilter(
		vethBHost,
		netlink.HANDLE_MIN_EGRESS,
		mgr.collection.Programs[TRACE_HOST_EGRESS_PROG_NAME],
	); err != nil {
		return err
	}
	if err := mgr.setFilter(
		vethBHost,
		netlink.HANDLE_MIN_INGRESS,
		mgr.collection.Programs[TRACE_HOST_INGRESS_PROG_NAME],
	); err != nil {
		return err
	}

	// VethB Peer Setting
	vethBPeer := tp.Endpoints[topology.VethBPeerName]
	if err := mgr.setQdisc(vethBPeer.Name, vethBPeer.Namespace); err != nil {
		return err
	}
	if err := mgr.setFilter(
		vethBPeer,
		netlink.HANDLE_MIN_INGRESS,
		mgr.collection.Programs[TRACE_PEER_INGRESS_PROG_NAME]); err != nil {
		return err
	}
	return nil
}

func (mgr *BPFManager) TestSetup(scenario string, tp *topology.Topology) (err error) {
	switch scenario {
	case "redirect":
		if err := mgr.collection.Maps[TEST_SELECT_MAP_NAME].Put(uint32(0), TEST_SELECT_REDIRECT); err != nil {
			return err
		}
	case "redirect_peer":
		if err := mgr.collection.Maps[TEST_SELECT_MAP_NAME].Put(uint32(0), TEST_SELECT_REDIRECT_PEER); err != nil {
			return err
		}
	default:
		return fmt.Errorf("scenario not exist")
	}

	return nil
}

func (mgr *BPFManager) ClearTraceMap() error {
	traceMap, ok := mgr.collection.Maps[TRACE_MAP]
	if !ok {
		return fmt.Errorf("trace map not found")
	}

	iter := traceMap.Iterate()
	var key uint32
	var val TraceInfo

	for iter.Next(&key, &val) {
		if err := traceMap.Delete(&key); err != nil {
			return fmt.Errorf("clear trace map key %d: %w", key, err)
		}
	}

	return iter.Err()
}

func (mgr *BPFManager) ReadTraceEntires() ([]TraceEntry, error) {
	traceMap, ok := mgr.collection.Maps[TRACE_MAP]
	if !ok {
		return nil, fmt.Errorf("trace map not found")
	}

	iter := traceMap.Iterate()
	var key uint32
	var val TraceInfo

	traces := make([]TraceEntry, 0)
	for iter.Next(&key, &val) {
		traces = append(traces, TraceEntry{Key: key, Value: val})
	}

	if err := iter.Err(); err != nil {
		return nil, fmt.Errorf("read trace map: %w", err)
	}

	return traces, nil
}

func (mgr *BPFManager) setQdisc(ifName, namespace string) error {
	logger := mgr.logger.With(
		"ifName", ifName,
		"namespace", namespace,
	)
	logger.Debug("configuring clsact qdisc")

	if err := topology.WithNetNameSpace(namespace, func() error {
		link, err := netlink.LinkByName(ifName)
		if err != nil {
			return fmt.Errorf("get link by name %s: %w", ifName, err)
		}

		clasact := &netlink.GenericQdisc{
			QdiscAttrs: netlink.QdiscAttrs{
				LinkIndex: link.Attrs().Index,
				Handle:    netlink.MakeHandle(QDISC_ID, 0),
				Parent:    netlink.HANDLE_CLSACT,
			},
			QdiscType: "clsact",
		}

		err = netlink.QdiscReplace(clasact)
		if err != nil {
			return fmt.Errorf("failed to replace clsact qdisc: %w", err)
		}

		return nil
	}); err != nil {
		return err
	}

	mgr.qdiscs[ifName] = tcQdiscRef{
		IfName:    ifName,
		Namespace: namespace,
	}

	logger.Info("clsact qdisc ready")

	return nil
}

func (mgr *BPFManager) setFilter(ep *topology.Endpoint, parent uint32, prog *ebpf.Program) error {
	logger := mgr.logger.With(
		"ifName", ep.Name,
		"namespace", ep.Namespace,
		"parent", fmt.Sprintf("%#x", parent),
		"program", prog.String(),
	)
	logger.Debug("attaching tc-bpf filter")

	info, err := prog.Info()
	if err != nil {
		return fmt.Errorf("get bpf prog info %s: %w", info.Name, err)
	}

	if err := topology.WithNetNameSpace(ep.Namespace, func() error {
		link, err := netlink.LinkByName(ep.Name)
		if err != nil {
			return fmt.Errorf("get link by name %s: %w", ep.Name, err)
		}

		filter := &netlink.BpfFilter{
			FilterAttrs: netlink.FilterAttrs{
				LinkIndex: link.Attrs().Index,
				Parent:    parent,
				Handle:    netlink.MakeHandle(0, 1),
				Protocol:  unix.ETH_P_ALL,
			},
			Fd:           prog.FD(),
			Name:         info.Name,
			DirectAction: true,
		}

		err = netlink.FilterReplace(filter)
		if err != nil {
			return fmt.Errorf("failed to replace tc bpf filter (parent=%#x): %w", parent, err)
		}

		ep.Programs = append(ep.Programs, topology.Program{Name: info.Name, Direction: directionString(parent)})

		return nil
	}); err != nil {
		return err
	}

	mgr.filters[info.Name] = tcFilterRef{
		IfName:    ep.Name,
		Namespace: ep.Namespace,
		Parent:    parent,
		Name:      info.Name,
	}
	logger.Info("tc-bpf filter ready")

	return nil
}

func directionString(parent uint32) string {
	switch parent {
	case netlink.HANDLE_MIN_INGRESS:
		return "ingress"
	case netlink.HANDLE_MIN_EGRESS:
		return "egress"
	default:
		return "unknown"
	}
}

func (mgr *BPFManager) Cleanup() error {
	var firstErr error

	for _, filter := range mgr.filters {
		if err := mgr.deleteFilter(filter.IfName, filter.Namespace, filter.Parent, filter.Name); err != nil {
			mgr.logger.With("filter", filter.Name).Error("delete filter", "err", err)
			if firstErr == nil {
				firstErr = err
			}
		}
	}

	for _, qdisc := range mgr.qdiscs {
		if err := mgr.deleteQdisc(qdisc.IfName, qdisc.Namespace); err != nil {
			mgr.logger.With("ifName", qdisc.IfName, "namespace", qdisc.Namespace).Error("delete qdisc", "err", err)
			if firstErr == nil {
				firstErr = err
			}
		}
	}

	mgr.collection.Close()
	mgr.logger.Info("BPF manager cleanup complete")

	return firstErr
}

// deleteFilter
func (mgr *BPFManager) deleteFilter(ifName, namespace string, parent uint32, name string) error {
	return topology.WithNetNameSpace(namespace, func() error {
		link, err := netlink.LinkByName(ifName)
		if err != nil {
			return fmt.Errorf("get link by name %s: %w", ifName, err)
		}

		filters, err := netlink.FilterList(link, parent)
		if err != nil {
			return fmt.Errorf("list ilters on %s: %w", ifName, err)
		}

		for _, filter := range filters {
			bpfFilter, ok := filter.(*netlink.BpfFilter)
			if !ok {
				continue
			}
			// parent + name 매칭
			if bpfFilter.Name == name && bpfFilter.Attrs().Parent == parent {
				err := netlink.FilterDel(filter)
				if err != nil {
					if errors.Is(err, unix.ENOENT) {
						err = nil
					} else {
						return fmt.Errorf("delete filter %s on %s: %w", name, ifName, err)
					}
				}
			}
		}

		delete(mgr.filters, name)

		return nil
	})
}

// deleteQdisc
func (mgr *BPFManager) deleteQdisc(ifName, namespace string) error {
	return topology.WithNetNameSpace(namespace, func() error {
		link, err := netlink.LinkByName(ifName)
		if err != nil {
			return fmt.Errorf("get link by name %s: %w", ifName, err)
		}

		clsact := &netlink.GenericQdisc{
			QdiscAttrs: netlink.QdiscAttrs{
				LinkIndex: link.Attrs().Index,
				Handle:    netlink.MakeHandle(QDISC_ID, 0),
				Parent:    netlink.HANDLE_CLSACT,
			},
			QdiscType: "clsact",
		}

		err = netlink.QdiscDel(clsact)
		if err != nil {
			if errors.Is(err, unix.ENOENT) {
				err = nil
			} else {
				return fmt.Errorf("delete clsact qdisc on %s: %w", ifName, err)
			}
		}

		delete(mgr.qdiscs, ifName)

		return nil
	})
}
