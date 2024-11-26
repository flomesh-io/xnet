package cli

import (
	"github.com/spf13/cobra"
)

const ifaceDescription = ``

func NewIFaceCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "iface",
		Short:   "iface",
		Long:    ifaceDescription,
		Aliases: []string{"if"},
		Args:    cobra.NoArgs,
	}
	cmd.AddCommand(newIFaceList())

	return cmd
}
