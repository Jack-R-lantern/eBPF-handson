package scenario

import (
	"context"
	"fmt"
	"os/exec"
	"sort"
	"time"

	"github.com/Jack-R-lantern/eBPF-handson/redirect/internal/bpf"
	"github.com/Jack-R-lantern/eBPF-handson/redirect/internal/logger"
	"github.com/Jack-R-lantern/eBPF-handson/redirect/internal/topology"
)

type EndpointRef struct {
	Namespace string `json:"namespace"`
	Interface string `json:"interface"`
}

type PathStep struct {
	Step      int           `json:"step"`
	Namespace string        `json:"namespace"`
	Interface string        `json:"interface"`
	Hook      string        `json:"hook"`
	Program   string        `json:"program"`
	At        time.Time     `json:"at,omitempty"`
	SincePrev time.Duration `json:"delta_ns,omitempty"`
	Note      string        `json:"note,omitempty"`
}

type Result struct {
	Scenario string      `json:"scenario"`
	From     EndpointRef `json:"from"`
	To       EndpointRef `json:"to"`
	Path     []PathStep  `json:"path"`
	Status   string      `json:"status"`
}

type Runner struct {
	bpfManager *bpf.BPFManager
	tp         *topology.Topology
}

func NewRunner(mgr *bpf.BPFManager, tp *topology.Topology) *Runner {
	return &Runner{
		bpfManager: mgr,
		tp:         tp,
	}
}

func (runner *Runner) Run(ctx context.Context, scenario string) (Result, error) {
	if err := runner.bpfManager.TestSetup(scenario, runner.tp); err != nil {
		return Result{}, nil
	}

	if err := runner.bpfManager.ClearTraceMap(); err != nil {
		return Result{}, err
	}

	dest := runner.tp.Endpoints[topology.VethBPeerName].IP.String()

	if log, ok := logger.FromContext(ctx); ok {
		log.With("scenario", scenario, "dest", dest).Info("running trace test")
	}

	if err := runPing(ctx, dest); err != nil {
		return Result{}, err
	}

	time.Sleep(50 * time.Millisecond)

	traces, err := runner.bpfManager.ReadTraceEntires()
	if err != nil {
		return Result{}, err
	}

	result := Result{
		Scenario: scenario,
		From:     EndpointRef{Namespace: topology.NamespaceA, Interface: topology.VethAPeerName},
		To:       EndpointRef{Namespace: topology.NamespaceB, Interface: topology.VethBPeerName},
		Path:     buildPath(traces, scenario),
		Status:   "ok",
	}

	return result, nil
}

func runPing(ctx context.Context, destination string) error {
	cctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

	cmd := exec.CommandContext(cctx, "ip", "netns", "exec", topology.NamespaceA, "ping", "-c", "1", "-W", "1", destination)

	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("ping failed: %w (output %s)", err, string(output))
	}
	return nil
}

func buildPath(traces []bpf.TraceEntry, scenario string) []PathStep {
	if len(traces) == 0 {
		return nil
	}

	sort.Slice(traces, func(i, j int) bool {
		return traces[i].Value.LastSeen < traces[j].Value.LastSeen
	})

	steps := make([]PathStep, 0, len(traces))
	baseline := traces[0].Value.LastSeen

	for i, trace := range traces {
		step := PathStep{Step: i + 1}

		switch {
		case trace.Value.TraversedPath&bpf.B_PEER_NAMESPACE_INGRESS != 0:
			step.Namespace = topology.NamespaceB
			step.Interface = topology.VethBPeerName
			step.Hook = "ingress"
			step.Program = bpf.TRACE_PEER_INGRESS_PROG_NAME
		case trace.Value.TraversedPath&bpf.B_HOST_NAMESPACE_EGRESS != 0:
			step.Namespace = topology.NamespaceRoot
			step.Interface = topology.VethBHostName
			step.Hook = "egress"
			step.Program = bpf.TRACE_HOST_EGRESS_PROG_NAME
		case trace.Value.TraversedPath&bpf.A_HOST_NAMESPACE_INGRESS != 0:
			step.Namespace = topology.NamespaceRoot
			step.Interface = topology.VethAHostName
			step.Hook = "ingress"
			step.Program = bpf.REDIRECT_TEST_PROG_NAME
		case trace.Value.TraversedPath&bpf.A_PEER_NAMESPACE_EGRESS != 0:
			step.Namespace = topology.NamespaceA
			step.Interface = topology.VethAPeerName
			step.Hook = "egress"
			step.Program = bpf.TRACE_PEER_EGRESS_PROG_NAME
		default:
			step.Namespace = "unknown"
			step.Interface = "unknown"
			step.Hook = "unknown"
		}

		elapsed := trace.Value.LastSeen - baseline
		if i == 0 {
			step.Note = "trace started"
			step.SincePrev = 0
		} else {
			step.SincePrev = time.Duration(elapsed)
			step.Note = fmt.Sprintf("+%.3f ms since first trace", float64(elapsed)/1_000_000)
		}

		if step.Program == bpf.REDIRECT_TEST_PROG_NAME {
			if scenario == "redirect_peer" {
				step.Note = step.Note + " - bpf_redirect_peer"
			} else {
				step.Note = step.Note + " - bpf_redirect"
			}
		}

		steps = append(steps, step)
	}

	return steps
}
