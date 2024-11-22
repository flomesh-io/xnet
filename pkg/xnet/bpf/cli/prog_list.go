package cli

import (
	"github.com/spf13/cobra"

	"github.com/flomesh-io/xnet/pkg/xnet/bpf/maps"
)

const progListDescription = ``
const progListExample = ``

type progListCmd struct {
}

func newProgList() *cobra.Command {
	progList := &progListCmd{}

	cmd := &cobra.Command{
		Use:     "list",
		Short:   "list progs",
		Long:    progListDescription,
		Aliases: []string{"l", "ls"},
		Args:    cobra.MinimumNArgs(0),
		RunE: func(cmd *cobra.Command, args []string) error {
			return progList.run()
		},
		Example: progListExample,
	}

	return cmd
}

func (a *progListCmd) run() error {
	maps.ShowProgEntries()
	return nil
}
