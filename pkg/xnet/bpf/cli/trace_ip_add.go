package cli

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/flomesh-io/xnet/pkg/xnet/bpf/maps"
	"github.com/flomesh-io/xnet/pkg/xnet/util"
)

const traceIPAddDescription = ``
const traceIPAddExample = ``

type traceIPAddCmd struct {
	sys
	sa
	tc
}

func newTraceIPAdd() *cobra.Command {
	traceIPAdd := &traceIPAddCmd{}

	cmd := &cobra.Command{
		Use:     "add",
		Short:   "add",
		Long:    traceIPAddDescription,
		Aliases: []string{"a"},
		Args:    cobra.MinimumNArgs(0),
		RunE: func(cmd *cobra.Command, args []string) error {
			return traceIPAdd.run()
		},
		Example: traceIPAddExample,
	}

	//add flags
	f := cmd.Flags()
	traceIPAdd.sys.addFlags(f)
	traceIPAdd.sa.addAddrFlag(f)
	traceIPAdd.tc.addFlags(f)

	return cmd
}

func (a *traceIPAddCmd) run() error {
	if a.addr.IsUnspecified() {
		return fmt.Errorf(`invalid addr: %s`, a.addr)
	}
	var err error
	traceKey := new(maps.TraceIPKey)
	if traceKey.Addr[0], err = util.IPv4ToInt(a.sa.addr); err != nil {
		return err
	}
	traceVal := new(maps.TraceIPVal)
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
	return maps.AddTraceIPEntry(a.sysId(), traceKey, traceVal)
}
