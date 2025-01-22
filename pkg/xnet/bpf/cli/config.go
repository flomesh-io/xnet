package cli

import (
	"github.com/spf13/cobra"
)

const configDescription = ``

func NewConfigCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "config",
		Short:   "config xnat",
		Long:    configDescription,
		Aliases: []string{"cfg"},
		Args:    cobra.NoArgs,
	}
	cmd.AddCommand(newConfigList())
	cmd.AddCommand(newConfigGet())
	cmd.AddCommand(newConfigSet())

	return cmd
}
