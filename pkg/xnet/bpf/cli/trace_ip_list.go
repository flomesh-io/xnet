package cli

import (
	"github.com/spf13/cobra"

	"github.com/flomesh-io/xnet/pkg/xnet/bpf/maps"
)

const traceIPListDescription = ``
const traceIPListExample = ``

type traceIPListCmd struct {
}

func newTraceIPList() *cobra.Command {
	traceIPList := &traceIPListCmd{}

	cmd := &cobra.Command{
		Use:     "list",
		Short:   "list",
		Long:    traceIPListDescription,
		Aliases: []string{"l", "ls"},
		Args:    cobra.MinimumNArgs(0),
		RunE: func(cmd *cobra.Command, args []string) error {
			return traceIPList.run()
		},
		Example: traceIPListExample,
	}

	return cmd
}

func (a *traceIPListCmd) run() error {
	maps.ShowTraceIPEntries()
	return nil
}
