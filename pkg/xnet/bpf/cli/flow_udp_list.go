package cli

import (
	"github.com/spf13/cobra"

	"github.com/flomesh-io/xnet/pkg/xnet/bpf/maps"
)

const udpFlowListDescription = ``
const udpFlowListExample = ``

type udpFlowListCmd struct {
}

func newUDPFlowList() *cobra.Command {
	flowList := &udpFlowListCmd{}

	cmd := &cobra.Command{
		Use:     "list",
		Short:   "list udp flows",
		Long:    udpFlowListDescription,
		Aliases: []string{"l", "ls"},
		Args:    cobra.MinimumNArgs(0),
		RunE: func(cmd *cobra.Command, args []string) error {
			return flowList.run()
		},
		Example: udpFlowListExample,
	}

	return cmd
}

func (a *udpFlowListCmd) run() error {
	maps.ShowUDPFlowEntries()
	return nil
}
