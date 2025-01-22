package cli

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/flomesh-io/xnet/pkg/xnet/bpf/maps"
)

const tcpFlowFlushDescription = ``
const tcpFlowFlushExample = ``

type tcpFlowFlushCmd struct {
	sys

	idleSeconds int
	batchSize   int
}

func newTCPFlowFlush() *cobra.Command {
	flowFlush := &tcpFlowFlushCmd{}

	cmd := &cobra.Command{
		Use:     "flush",
		Short:   "flush idle tcp flows",
		Long:    tcpFlowFlushDescription,
		Aliases: []string{"f", "fl"},
		Args:    cobra.MinimumNArgs(0),
		RunE: func(cmd *cobra.Command, args []string) error {
			return flowFlush.run()
		},
		Example: tcpFlowFlushExample,
	}

	//add flags
	f := cmd.Flags()
	flowFlush.sys.addFlags(f)
	f.IntVar(&flowFlush.idleSeconds, "idle-seconds", 3600, "--idle-seconds=3600")
	f.IntVar(&flowFlush.batchSize, "batch-size", 1024, "--batch-size=1024")

	return cmd
}

func (a *tcpFlowFlushCmd) run() error {
	items, err := maps.FlushIdleTCPFlowEntries(a.sysId(), a.idleSeconds, a.batchSize)
	if err != nil {
		return err
	}
	fmt.Printf("flush %d items.\n", items)
	return nil
}
