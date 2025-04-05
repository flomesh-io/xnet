package cli

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/flomesh-io/xnet/pkg/xnet/bpf/maps"
	"github.com/flomesh-io/xnet/pkg/xnet/util"
)

const traceIPDelDescription = ``
const traceIPDelExample = ``

type traceIPDelCmd struct {
	sys
	sa
}

func newTraceIPDel() *cobra.Command {
	traceIPDel := &traceIPDelCmd{}

	cmd := &cobra.Command{
		Use:     "del",
		Short:   "del",
		Long:    traceIPDelDescription,
		Aliases: []string{"d"},
		Args:    cobra.MinimumNArgs(0),
		RunE: func(cmd *cobra.Command, args []string) error {
			return traceIPDel.run()
		},
		Example: traceIPDelExample,
	}

	//add flags
	f := cmd.Flags()
	traceIPDel.sys.addFlags(f)
	traceIPDel.addAddrFlag(f)

	return cmd
}

func (a *traceIPDelCmd) run() error {
	if a.addr.IsUnspecified() {
		return fmt.Errorf(`invalid addr: %s`, a.addr)
	}
	var err error
	traceKey := new(maps.TraceIPKey)
	if traceKey.Addr[0], traceKey.Addr[1], traceKey.Addr[2], traceKey.Addr[3], _, err = util.IPToInt(a.addr); err != nil {
		return err
	}
	return maps.DelTraceIPEntry(a.sysId(), traceKey)
}
