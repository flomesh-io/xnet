package cli

import (
	"github.com/spf13/cobra"

	"github.com/flomesh-io/xnet/pkg/xnet/bpf/maps"
)

const natListDescription = ``
const natListExample = ``

type natListCmd struct {
}

func newNatList() *cobra.Command {
	natList := &natListCmd{}

	cmd := &cobra.Command{
		Use:     "list",
		Short:   "list nats",
		Long:    natListDescription,
		Aliases: []string{"l", "ls"},
		Args:    cobra.MinimumNArgs(0),
		RunE: func(cmd *cobra.Command, args []string) error {
			return natList.run()
		},
		Example: natListExample,
	}

	return cmd
}

func (a *natListCmd) run() error {
	maps.ShowNatEntries()
	return nil
}
