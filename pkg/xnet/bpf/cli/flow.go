package cli

import (
	"github.com/spf13/cobra"
)

const flowDescription = ``

func NewFlowCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "flow",
		Short: "flow",
		Long:  flowDescription,
		Args:  cobra.NoArgs,
	}
	cmd.AddCommand(NewTCPFlowCmd())
	cmd.AddCommand(NewUDPFlowCmd())

	return cmd
}
