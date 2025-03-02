package cli

import (
	"github.com/spf13/cobra"
)

const arpDescription = ``

func NewArpCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "arp",
		Short:   "arp",
		Long:    arpDescription,
		Aliases: []string{"arp"},
		Args:    cobra.NoArgs,
	}
	cmd.AddCommand(newArpAnnounce())

	return cmd
}
