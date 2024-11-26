package cli

import (
	"github.com/spf13/cobra"

	"github.com/flomesh-io/xnet/pkg/xnet/bpf/maps"
)

const ifaceListDescription = ``
const ifaceListExample = ``

type ifaceListCmd struct {
}

func newIFaceList() *cobra.Command {
	ifaceList := &ifaceListCmd{}

	cmd := &cobra.Command{
		Use:     "list",
		Short:   "list ifaces",
		Long:    ifaceListDescription,
		Aliases: []string{"l", "ls"},
		Args:    cobra.MinimumNArgs(0),
		RunE: func(cmd *cobra.Command, args []string) error {
			return ifaceList.run()
		},
		Example: ifaceListExample,
	}

	return cmd
}

func (a *ifaceListCmd) run() error {
	maps.ShowIFaceEntries()
	return nil
}
