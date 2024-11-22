package cli

import (
	"github.com/spf13/cobra"
)

const tcpOptDescription = ``

func NewTCPOptCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "tcp",
		Short: "tcp",
		Long:  tcpOptDescription,
		Args:  cobra.NoArgs,
	}
	cmd.AddCommand(newTCPOptList())

	return cmd
}
