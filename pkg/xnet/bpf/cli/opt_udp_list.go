package cli

import (
	"github.com/spf13/cobra"

	"github.com/flomesh-io/xnet/pkg/xnet/bpf/maps"
)

const udpOptListDescription = ``
const udpOptListExample = ``

type udpOptListCmd struct {
}

func newUDPOptList() *cobra.Command {
	udpOptList := &udpOptListCmd{}

	cmd := &cobra.Command{
		Use:     "list",
		Short:   "list opts",
		Long:    udpOptListDescription,
		Aliases: []string{"l", "ls"},
		Args:    cobra.MinimumNArgs(0),
		RunE: func(cmd *cobra.Command, args []string) error {
			return udpOptList.run()
		},
		Example: udpOptListExample,
	}

	return cmd
}

func (a *udpOptListCmd) run() error {
	maps.ShowUDPOptEntries()
	return nil
}
