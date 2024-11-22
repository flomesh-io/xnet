package cli

import (
	"github.com/spf13/cobra"
)

const tcpFlowDescription = ``

func NewTCPFlowCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "tcp",
		Short: "tcp",
		Long:  tcpFlowDescription,
		Args:  cobra.NoArgs,
	}
	cmd.AddCommand(newTCPFlowList())
	cmd.AddCommand(newTCPFlowFlush())

	return cmd
}
