package cli

import (
	"github.com/spf13/cobra"
)

const convDescription = ``

func NewConvCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "conv",
		Short: "conv",
		Long:  convDescription,
		Args:  cobra.NoArgs,
	}
	cmd.AddCommand(newIP2Int())
	cmd.AddCommand(newInt2IP())
	cmd.AddCommand(newHtons())
	cmd.AddCommand(newNtohs())
	return cmd
}
