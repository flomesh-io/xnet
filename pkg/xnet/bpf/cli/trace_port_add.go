package cli

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/flomesh-io/xnet/pkg/xnet/bpf/maps"
	"github.com/flomesh-io/xnet/pkg/xnet/util"
)

const tracePortAddDescription = ``
const tracePortAddExample = ``

type tracePortAddCmd struct {
	sys
	sa
	tc
}

func newTracePortAdd() *cobra.Command {
	tracePortAdd := &tracePortAddCmd{}

	cmd := &cobra.Command{
		Use:     "add",
		Short:   "add",
		Long:    tracePortAddDescription,
		Aliases: []string{"a"},
		Args:    cobra.MinimumNArgs(0),
		RunE: func(cmd *cobra.Command, args []string) error {
			return tracePortAdd.run()
		},
		Example: tracePortAddExample,
	}

	//add flags
	f := cmd.Flags()
	tracePortAdd.sys.addFlags(f)
	tracePortAdd.sa.addPortFlag(f)
	tracePortAdd.tc.addFlags(f)

	return cmd
}

func (a *tracePortAddCmd) run() error {
	if a.port <= 0 {
		return fmt.Errorf(`invalid port: %d`, a.port)
	}
	traceKey := new(maps.TracePortKey)
	traceKey.Port = util.HostToNetShort(a.port)
	traceVal := new(maps.TracePortVal)
	if a.tcIngress {
		traceVal.TcDir[maps.TC_DIR_IGR] = 1
	} else {
		traceVal.TcDir[maps.TC_DIR_IGR] = 0
	}
	if a.tcEgress {
		traceVal.TcDir[maps.TC_DIR_EGR] = 1
	} else {
		traceVal.TcDir[maps.TC_DIR_EGR] = 0
	}
	return maps.AddTracePortEntry(a.sysId(), traceKey, traceVal)
}
