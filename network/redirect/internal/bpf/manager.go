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
	REDIRECT_TEST_PROG_NAME      = "redirect_test"
	REDIRECT_PEER_TEST_PROG_NAME = "redirect_peer_test"

	ENDPOINTS_MAP_NAME    = "endpoints"
	REDIRECT_DIR_MAP_NAME = "redirect_dir"

	TRACE_HOST_INGRESS_PROG_NAME = "trace_host_ingress"
	TRACE_PEER_INGRESS_PROG_NAME = "trace_peer_ingress"
	TRACE_HOST_EGRESS_PROG_NAME  = "trace_host_egress"

	TRACE_HOST_INGRESS_MAP_NAME = "trace_host_ingress_map"
	TRACE_PEER_INGRESS_MAP_NAME = "trace_peer_ingress_map"
	TRACE_HOST_EGRESS_MAP_NAME  = "trace_host_egress_map"

	QDISC_ID = 0xffff
)

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
	// VethB Host Setting
	if err := mgr.setQdisc(tp.BHost.Name, tp.BHost.Namespace); err != nil {
		return err
	}
	if err := mgr.setFilter(
		tp.BHost.Name, tp.BHost.Namespace,
		netlink.HANDLE_MIN_INGRESS,
		mgr.collection.Programs[TRACE_HOST_INGRESS_PROG_NAME],
	); err != nil {
		return err
	}
	if err := mgr.setFilter(
		tp.BHost.Name, tp.BHost.Namespace,
		netlink.HANDLE_MIN_EGRESS,
		mgr.collection.Programs[TRACE_HOST_EGRESS_PROG_NAME],
	); err != nil {
		return err
	}

	// VethB Peer Setting
	if err := mgr.setQdisc(tp.BPeer.Name, tp.BPeer.Namespace); err != nil {
		return err
	}
	if err := mgr.setFilter(
		tp.BPeer.Name, tp.BPeer.Namespace,
		netlink.HANDLE_MIN_INGRESS,
		mgr.collection.Programs[TRACE_PEER_INGRESS_PROG_NAME]); err != nil {
		return err
	}
	return nil
}

func (mgr *BPFManager) TestSetup(scenario string, tp *topology.Topology) (err error) {
	err = mgr.deleteQdisc(tp.AHost.Name, tp.AHost.Namespace)
	if err != nil {
		return err
	}
	err = mgr.setQdisc(tp.AHost.Name, tp.AHost.Namespace)
	if err != nil {
		return err
	}

	redirect_flag := 0

	switch scenario {
	case "redirect_egress":
		err = mgr.setFilter(tp.AHost.Name, tp.AHost.Namespace,
			netlink.HANDLE_MIN_INGRESS,
			mgr.collection.Programs[REDIRECT_TEST_PROG_NAME],
		)
	case "redirect_ingress":
		redirect_flag = unix.BPF_F_INGRESS
		err = mgr.setFilter(tp.AHost.Name, tp.AHost.Namespace,
			netlink.HANDLE_MIN_INGRESS,
			mgr.collection.Programs[REDIRECT_TEST_PROG_NAME],
		)
	case "redirect_peer":
		err = mgr.setFilter(tp.AHost.Name, tp.AHost.Namespace,
			netlink.HANDLE_MIN_INGRESS,
			mgr.collection.Programs[REDIRECT_PEER_TEST_PROG_NAME],
		)
	default:
		return fmt.Errorf("scenario not exist")
	}

	if err != nil {
		return err
	}

	if err := mgr.setRedirectDir(uint32(redirect_flag)); err != nil {
		return err
	}

	return nil
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

func (mgr *BPFManager) setFilter(ifName, namespace string, parent uint32, prog *ebpf.Program) error {
	logger := mgr.logger.With(
		"ifName", ifName,
		"namespace", namespace,
		"parent", fmt.Sprintf("%#x", parent),
		"program", prog.String(),
	)
	logger.Debug("attaching tc-bpf filter")

	if err := topology.WithNetNameSpace(namespace, func() error {
		link, err := netlink.LinkByName(ifName)
		if err != nil {
			return fmt.Errorf("get link by name %s: %w", ifName, err)
		}

		filter := &netlink.BpfFilter{
			FilterAttrs: netlink.FilterAttrs{
				LinkIndex: link.Attrs().Index,
				Parent:    parent,
				Handle:    netlink.MakeHandle(0, 1),
				Protocol:  unix.ETH_P_ALL,
			},
			Fd:           prog.FD(),
			Name:         prog.String(),
			DirectAction: true,
		}

		err = netlink.FilterReplace(filter)
		if err != nil {
			return fmt.Errorf("failed to replace tc bpf filter (parent=%#x): %w", parent, err)
		}
		return nil
	}); err != nil {
		return err
	}

	mgr.filters[prog.String()] = tcFilterRef{
		IfName:    ifName,
		Namespace: namespace,
		Parent:    parent,
		Name:      prog.String(),
	}
	logger.Info("tc-bpf filter ready")

	return nil
}

func (mgr *BPFManager) setRedirectDir(flag uint32) error {
	mgr.logger.With("direction", flag).Debug("setting redirect direction")
	dirMap, ok := mgr.collection.Maps[REDIRECT_DIR_MAP_NAME]
	if !ok {
		return fmt.Errorf("redirect_dir map not found in collection")
	}

	key := uint32(0)
	value := flag

	if err := dirMap.Update(&key, &value, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("failed to update redirect_dir map: %w", err)
	}
	mgr.logger.With("direction", flag).Info("redirect direction updated")
	return nil
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
				if errors.Is(err, unix.ENOENT) {
					err = nil
				} else {
					return fmt.Errorf("delete filter %s on %s: %w", name, ifName, err)
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
		if errors.Is(err, unix.ENOENT) {
			err = nil
		} else {
			return fmt.Errorf("delete clsact qdisc on %s: %w", ifName, err)
		}

		delete(mgr.qdiscs, ifName)

		return nil
	})
}
