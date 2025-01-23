package cli

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/flomesh-io/xnet/pkg/xnet/bpf/maps"
	"github.com/flomesh-io/xnet/pkg/xnet/util"
)

const tracePortDelDescription = ``
const tracePortDelExample = ``

type tracePortDelCmd struct {
	sys
	sa
}

func newTracePortDel() *cobra.Command {
	tracePortDel := &tracePortDelCmd{}

	cmd := &cobra.Command{
		Use:     "del",
		Short:   "del",
		Long:    tracePortDelDescription,
		Aliases: []string{"d"},
		Args:    cobra.MinimumNArgs(0),
		RunE: func(cmd *cobra.Command, args []string) error {
			return tracePortDel.run()
		},
		Example: tracePortDelExample,
	}

	//add flags
	f := cmd.Flags()
	tracePortDel.sys.addFlags(f)
	tracePortDel.sa.addPortFlag(f)

	return cmd
}

func (a *tracePortDelCmd) run() error {
	if a.port <= 0 {
		return fmt.Errorf(`invalid port: %d`, a.port)
	}
	traceKey := new(maps.TracePortKey)
	traceKey.Port = util.HostToNetShort(a.port)
	return maps.DelTracePortEntry(a.sysId(), traceKey)
}
