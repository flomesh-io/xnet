package cli

import (
	"github.com/spf13/cobra"
)

const netnsDescription = ``

func NewNetnsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "netns",
		Short: "netns",
		Long:  netnsDescription,
		Args:  cobra.NoArgs,
	}
	cmd.AddCommand(newNetnsList())
	cmd.AddCommand(newNetnsExec())

	return cmd
}
