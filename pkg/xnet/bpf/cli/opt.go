package cli

import (
	"github.com/spf13/cobra"
)

const optDescription = ``

func NewOptCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "opt",
		Short: "opt",
		Long:  optDescription,
		Args:  cobra.NoArgs,
	}
	cmd.AddCommand(NewTCPOptCmd())
	cmd.AddCommand(NewUDPOptCmd())

	return cmd
}
