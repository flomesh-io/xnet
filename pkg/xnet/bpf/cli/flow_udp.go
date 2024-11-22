package cli

import (
	"github.com/spf13/cobra"
)

const udpFlowDescription = ``

func NewUDPFlowCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "udp",
		Short: "udp",
		Long:  udpFlowDescription,
		Args:  cobra.NoArgs,
	}
	cmd.AddCommand(newUDPFlowList())
	cmd.AddCommand(newUDPFlowFlush())

	return cmd
}
