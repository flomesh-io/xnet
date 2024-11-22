package cli

import (
	"github.com/spf13/cobra"

	"github.com/flomesh-io/xnet/pkg/xnet/bpf/maps"
)

const progInitDescription = ``
const progInitExample = ``

type progInitCmd struct {
}

func newProgInit() *cobra.Command {
	progInit := &progInitCmd{}

	cmd := &cobra.Command{
		Use:     "init",
		Short:   "init progs",
		Long:    progInitDescription,
		Aliases: []string{"l", "ls"},
		Args:    cobra.MinimumNArgs(0),
		RunE: func(cmd *cobra.Command, args []string) error {
			return progInit.run()
		},
		Example: progInitExample,
	}

	return cmd
}

func (a *progInitCmd) run() error {
	return maps.InitProgEntries()
}
