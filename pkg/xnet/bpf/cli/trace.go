package cli

import (
	"github.com/spf13/cobra"
)

const traceDescription = ``

func NewTraceCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "trace",
		Short:   "trace",
		Long:    traceDescription,
		Aliases: []string{"tr"},
		Args:    cobra.NoArgs,
	}
	cmd.AddCommand(NewTraceIPCmd())
	cmd.AddCommand(NewTracePortCmd())

	return cmd
}
