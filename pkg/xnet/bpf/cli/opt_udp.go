package cli

import (
	"github.com/spf13/cobra"
)

const udpOptDescription = ``

func NewUDPOptCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "udp",
		Short: "udp",
		Long:  udpOptDescription,
		Args:  cobra.NoArgs,
	}
	cmd.AddCommand(newUDPOptList())

	return cmd
}
