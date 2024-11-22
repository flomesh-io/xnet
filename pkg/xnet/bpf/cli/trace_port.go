package cli

import (
	"github.com/spf13/cobra"
)

const tracePortDescription = ``

func NewTracePortCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "port",
		Short: "port",
		Long:  tracePortDescription,
		Args:  cobra.NoArgs,
	}
	cmd.AddCommand(newTracePortList())
	cmd.AddCommand(newTracePortAdd())
	cmd.AddCommand(newTracePortDel())

	return cmd
}
