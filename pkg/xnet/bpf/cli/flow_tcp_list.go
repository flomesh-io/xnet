package cli

import (
	"github.com/spf13/cobra"

	"github.com/flomesh-io/xnet/pkg/xnet/bpf/maps"
)

const tcpFlowListDescription = ``
const tcpFlowListExample = ``

type tcpFlowListCmd struct {
}

func newTCPFlowList() *cobra.Command {
	flowList := &tcpFlowListCmd{}

	cmd := &cobra.Command{
		Use:     "list",
		Short:   "list tcp flows",
		Long:    tcpFlowListDescription,
		Aliases: []string{"l", "ls"},
		Args:    cobra.MinimumNArgs(0),
		RunE: func(cmd *cobra.Command, args []string) error {
			return flowList.run()
		},
		Example: tcpFlowListExample,
	}

	return cmd
}

func (a *tcpFlowListCmd) run() error {
	maps.ShowTCPFlowEntries()
	return nil
}
