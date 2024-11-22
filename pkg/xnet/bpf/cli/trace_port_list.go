package cli

import (
	"github.com/spf13/cobra"

	"github.com/flomesh-io/xnet/pkg/xnet/bpf/maps"
)

const tracePortListDescription = ``
const tracePortListExample = ``

type tracePortListCmd struct {
}

func newTracePortList() *cobra.Command {
	tracePortList := &tracePortListCmd{}

	cmd := &cobra.Command{
		Use:     "list",
		Short:   "list",
		Long:    tracePortListDescription,
		Aliases: []string{"l", "ls"},
		Args:    cobra.MinimumNArgs(0),
		RunE: func(cmd *cobra.Command, args []string) error {
			return tracePortList.run()
		},
		Example: tracePortListExample,
	}

	return cmd
}

func (a *tracePortListCmd) run() error {
	maps.ShowTracePortEntries()
	return nil
}
