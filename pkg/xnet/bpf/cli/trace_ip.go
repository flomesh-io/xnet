package cli

import (
	"github.com/spf13/cobra"
)

const tripDescription = ``

func NewTraceIPCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "ip",
		Short: "ip",
		Long:  tripDescription,
		Args:  cobra.NoArgs,
	}
	cmd.AddCommand(newTraceIPList())
	cmd.AddCommand(newTraceIPAdd())
	cmd.AddCommand(newTraceIPDel())

	return cmd
}
