package cli

import (
	"github.com/spf13/cobra"
)

const progDescription = ``

func NewProgCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "prog",
		Short: "prog",
		Long:  progDescription,
		Args:  cobra.NoArgs,
	}
	cmd.AddCommand(newProgList())
	cmd.AddCommand(newProgInit())

	return cmd
}
