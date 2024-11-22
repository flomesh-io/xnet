package cli

import (
	"github.com/spf13/cobra"

	"github.com/flomesh-io/xnet/pkg/xnet/bpf/maps"
)

const tcpOptListDescription = ``
const tcpOptListExample = ``

type tcpOptListCmd struct {
}

func newTCPOptList() *cobra.Command {
	tcpOptList := &tcpOptListCmd{}

	cmd := &cobra.Command{
		Use:     "list",
		Short:   "list opts",
		Long:    tcpOptListDescription,
		Aliases: []string{"l", "ls"},
		Args:    cobra.MinimumNArgs(0),
		RunE: func(cmd *cobra.Command, args []string) error {
			return tcpOptList.run()
		},
		Example: tcpOptListExample,
	}

	return cmd
}

func (a *tcpOptListCmd) run() error {
	maps.ShowTCPOptEntries()
	return nil
}
